package cmd

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/cloudflare/cloudflare-go/v6"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var addCmd = &cobra.Command{
	Use:   "add [profile]",
	Short: "Add a new profile to your configuration and keychain",
	Long:  "",
	Example: `
  Add a new profile (you will be prompted for credentials)

    $ cf-vault add example-profile

  Add a read-only short lived token profile restricted to a single account

    $ cf-vault add example-profile --profile-template read-only --session-duration 15m --account-id 01a7362d577a6c3019a474fd6f485823

  Add a read-only short lived token profile from an account API token

    $ cf-vault add example-profile --owner-account-id 01a7362d577a6c3019a474fd6f485823 --profile-template read-only --session-duration 15m

  Add a profile without prompting, reading an API token from stdin

    $ printf '%s' "$TOKEN" | cf-vault add example-profile --authentication-value-stdin

  Add a profile without prompting, reading a global API key from the environment

    $ CF_VAULT_AUTH_VALUE="$API_KEY" cf-vault add example-profile --email jacob@example.com
`,
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) < 1 {
			return errProfileArgRequired
		}
		return cobra.ExactArgs(1)(cmd, args)
	},
	RunE: runAdd,
}

func runAdd(cmd *cobra.Command, args []string) error {
	profileName := args[0]
	if err := validateProfileName(profileName); err != nil {
		return err
	}
	sessionDuration, _ := cmd.Flags().GetString(flagSessionDuration)
	profileTemplate, _ := cmd.Flags().GetString(flagProfileTemplate)
	accountIDs, _ := cmd.Flags().GetStringSlice(flagAccountID)
	zoneIDs, _ := cmd.Flags().GetStringSlice(flagZoneID)
	ownerAccountID, _ := cmd.Flags().GetString(flagOwnerAccountID)
	useSecureEnclave, _ := cmd.Flags().GetBool(flagSecureEnclave)
	useYubikey, _ := cmd.Flags().GetBool(flagYubikey)
	emailAddress, _ := cmd.Flags().GetString(flagEmail)
	authValueFromStdin, _ := cmd.Flags().GetBool(flagAuthValueStdin)
	force, _ := cmd.Flags().GetBool(flagForce)

	if err := validatePolicyTemplate(profileTemplate); err != nil {
		return err
	}
	if sessionDuration != "" {
		if _, err := parseSessionDuration(sessionDuration); err != nil {
			return fmt.Errorf(errFmtInvalidSessionDurationFlag, err)
		}
	}

	if profileTemplate == "" && (len(accountIDs) > 0 || len(zoneIDs) > 0) {
		return errResourceIDsNeedTemplate
	}
	if err := validateResourceIDs("account", accountIDs); err != nil {
		return err
	}
	if err := validateResourceIDs("zone", zoneIDs); err != nil {
		return err
	}

	var secretBackend string
	switch {
	case useSecureEnclave:
		secretBackend = secretBackendAgeSE
	case useYubikey:
		secretBackend = secretBackendAgeYubikey
	}

	configDir, err := resolveConfigDir()
	if err != nil {
		return err
	}
	configPath := filepath.Join(configDir, configFileName)

	// A config that fails to parse must stop here: carrying on with an empty
	// profile map would pass the existence check below and then overwrite the
	// file, deleting every profile in it.
	config, err := loadConfig(configPath)
	if err != nil {
		return err
	}
	if config.Profiles == nil {
		config.Profiles = make(map[string]profile)
	}

	// Checked before reading any credentials so an accidental overwrite
	// fails without the user entering (or piping) a secret for nothing.
	previous, exists := config.Profiles[profileName]
	if exists && !force {
		return fmt.Errorf(errFmtProfileExists, profileName, configPath)
	}

	creds, err := readCredentials(credentials{email: emailAddress, ownerAccountID: ownerAccountID}, authValueFromStdin)
	if err != nil {
		return err
	}
	emailAddress, ownerAccountID, authValue, authType := creds.email, creds.ownerAccountID, creds.authValue, creds.authType

	// Global API keys authenticate with the email alongside the key; API
	// tokens carry the identity themselves.
	if authType == authTypeAPIKey && emailAddress == "" {
		return errEmailRequiredForAPIKey
	}

	// Scannable tokens say who owns them, so a mismatched flag is caught here;
	// a legacy token's owner can only be taken from the flag.
	switch {
	case ownerAccountID != "" && authType == authTypeAPIKey:
		return errOwnerAccountIDForAPIKey
	case ownerAccountID != "" && strings.HasPrefix(authValue, userAPITokenPrefix):
		return errOwnerAccountIDForUserToken
	case ownerAccountID == "" && strings.HasPrefix(authValue, accountAPITokenPrefix):
		return errOwnerAccountIDRequired
	}
	if ownerAccountID != "" {
		if err := validateResourceIDs("owner account", []string{ownerAccountID}); err != nil {
			return err
		}
		for _, id := range accountIDs {
			if id != ownerAccountID {
				return fmt.Errorf(errFmtAccountOutsideOwner, ownerAccountID, id)
			}
		}
	}

	newProfile := profile{
		Email:           emailAddress,
		AuthType:        authType,
		OwnerAccountID:  ownerAccountID,
		SessionDuration: sessionDuration,
		SecretBackend:   secretBackend,
	}

	if profileTemplate != "" {
		cfClient := newClient(authValue, authType, emailAddress)
		generatedPolicy, err := generatePolicy(context.Background(), cfClient, profileTemplate, ownerAccountID, accountIDs, zoneIDs)
		if err != nil {
			return err
		}
		newProfile.Policies = generatedPolicy
	}

	log.Debugf("new profile: %+v", newProfile)

	// Persist the credential first — if storage fails we don't want an
	// orphaned profile entry in config.toml pointing at nothing.
	store, err := openSecretStore(configDir, profileName, newProfile)
	if err != nil {
		return err
	}
	if err := store.Set([]byte(authValue)); err != nil {
		return err
	}

	successMessage := msgSuccessKeyring
	if backend, ok := ageBackends[secretBackend]; ok {
		successMessage = backend.successMessage
	}

	config.Profiles[profileName] = newProfile
	if err := saveConfig(configPath, config); err != nil {
		return err
	}

	// Only once nothing refers to it any more, drop the credential of the
	// profile that was replaced, unless storing the new one overwrote it.
	if exists && !sameSecretLocation(previous, newProfile) {
		replaced, err := openSecretStore(configDir, profileName, previous)
		if err == nil {
			err = replaced.Delete()
		}
		if err != nil {
			log.Warnf(msgFmtReplacedSecretNotRemoved, err)
		}
	}

	fmt.Println(successMessage)
	return nil
}

// profileNameRE restricts profile names to a filesystem-safe subset. Profile
// names flow into filesystem paths (secrets/<name>.age, keyring keys) and
// TOML section names, so `..`, path separators, and leading dots must be
// rejected to prevent a crafted name from escaping the config directory or
// creating hidden files.
var profileNameRE = regexp.MustCompile(`^[A-Za-z0-9_-][A-Za-z0-9._-]*$`)

func validateProfileName(name string) error {
	if name == "" {
		return errProfileNameEmpty
	}
	if !profileNameRE.MatchString(name) {
		return fmt.Errorf(errFmtInvalidProfileName, name)
	}
	return nil
}

// resourceIDRE matches Cloudflare account and zone identifiers. IDs are
// interpolated into policy resource keys, so anything else (wildcards, dots)
// must be rejected to avoid silently widening or corrupting the scope.
var resourceIDRE = regexp.MustCompile(`^[0-9a-f]{32}$`)

func validateResourceIDs(kind string, ids []string) error {
	for _, id := range ids {
		if !resourceIDRE.MatchString(id) {
			return fmt.Errorf(errFmtInvalidResourceID, kind, id)
		}
	}
	return nil
}

// Credential formats, per
// https://developers.cloudflare.com/fundamentals/api/get-started/token-formats/.
// The scannable formats are a prefix, a 40 character body and a checksum
// whose length isn't documented, so only a lower bound is enforced.
var (
	scannableAPITokenRE = regexp.MustCompile(`^cf[ua]t_[A-Za-z0-9]{40,}$`)
	scannableAPIKeyRE   = regexp.MustCompile(`^cfk_[A-Za-z0-9]{40,}$`)
	legacyAPIKeyRE      = regexp.MustCompile(`^[0-9a-f]{37,45}$`)
	legacyAPITokenRE    = regexp.MustCompile(`^[A-Za-z0-9_-]{40}$`)
)

func determineAuthType(s string) (string, error) {
	switch {
	case scannableAPITokenRE.MatchString(s):
		log.Debug("API token detected")
		return authTypeAPIToken, nil
	case scannableAPIKeyRE.MatchString(s):
		log.Debug("API key detected")
		return authTypeAPIKey, nil
	// A 40 character lowercase hex value fits both legacy formats. Keys are
	// always hex whereas tokens are mixed case, so favour the key.
	case legacyAPIKeyRE.MatchString(s):
		log.Debug("API key detected")
		return authTypeAPIKey, nil
	case legacyAPITokenRE.MatchString(s):
		log.Debug("API token detected")
		return authTypeAPIToken, nil
	default:
		return "", errInvalidAuthValueFormat
	}
}

// policyTemplates are the values accepted by `--profile-template`.
var policyTemplates = []string{policyTemplateReadOnly, policyTemplateWriteEverything}

// validatePolicyTemplate rejects unknown template names up front, before the
// user is asked for credentials that would only be thrown away.
func validatePolicyTemplate(name string) error {
	if name == "" || slices.Contains(policyTemplates, name) {
		return nil
	}
	return fmt.Errorf(errFmtUnknownPolicyTemplate, name)
}

// maxAuthValueSize bounds how much of stdin `--authentication-value-stdin`
// reads. Every credential format is well under 100 bytes, so this leaves room
// for surrounding whitespace while refusing to buffer an unbounded stream
// such as a file or device piped in by mistake.
const maxAuthValueSize = 1024

// credentials are what `add` stores for a new profile. Fields left empty by
// the flags may be filled in from stdin, the environment or a prompt.
type credentials struct {
	email          string
	ownerAccountID string
	authValue      string
	authType       string
}

// readCredentials completes the credentials passed as flags with the
// authentication value and its type. The value comes from the first
// available of:
//
//  1. stdin, when `--authentication-value-stdin` is set
//  2. the CF_VAULT_AUTH_VALUE environment variable
//  3. an interactive prompt, followed by one for whatever else that kind of
//     credential needs and the flags didn't give
//
// The non-interactive sources never prompt: without a terminal there is nobody
// to answer, and a prompt reading from piped stdin would consume the secret.
func readCredentials(flags credentials, fromStdin bool) (credentials, error) {
	creds := flags
	var err error
	stdinFd := int(os.Stdin.Fd())
	switch envValue, fromEnv := os.LookupEnv(envAuthValue); {
	case fromStdin:
		creds.authValue, err = readAuthValueFromStdin()
	case fromEnv:
		creds.authValue = strings.TrimSpace(envValue)
	case term.IsTerminal(stdinFd):
		readPassword := func() ([]byte, error) { return term.ReadPassword(stdinFd) }
		return promptCredentials(flags, readPassword, os.Stdin, os.Stdout)
	default:
		err = errAuthValueSourceRequired
	}
	if err != nil {
		return credentials{}, fmt.Errorf(errFmtReadAuthValue, err)
	}

	creds.authType, err = determineAuthType(creds.authValue)
	if err != nil {
		return credentials{}, fmt.Errorf(errFmtDetectAuthType, err)
	}
	return creds, nil
}

// readAuthValueFromStdin reads the authentication value piped to stdin.
func readAuthValueFromStdin() (string, error) {
	// Reading a terminal to EOF would echo the secret as it is typed, with no
	// prompt to say input is expected; the interactive prompt exists for that
	// case.
	if term.IsTerminal(int(os.Stdin.Fd())) {
		return "", errAuthValueStdinIsTerminal
	}
	// Read one byte past the limit so an oversized value can be told apart
	// from one that is exactly at it.
	b, err := io.ReadAll(io.LimitReader(os.Stdin, maxAuthValueSize+1))
	if err != nil {
		return "", err
	}
	if len(b) > maxAuthValueSize {
		return "", errAuthValueTooLong
	}
	return strings.TrimSpace(string(b)), nil
}

// promptCredentials asks for the authentication value, then for only what
// that kind of credential needs and the flags didn't give: the email for a
// global API key, or the owning account's ID for an account API token. Other
// API tokens carry their identity themselves. readPassword reads the value
// without echoing it and in supplies the other answers, so tests can stand in
// for the terminal.
func promptCredentials(flags credentials, readPassword func() ([]byte, error), in io.Reader, out io.Writer) (credentials, error) {
	creds := flags
	fmt.Fprint(out, promptAuthValue)
	b, err := readPassword()
	fmt.Fprintln(out)
	if err != nil {
		return credentials{}, fmt.Errorf(errFmtReadAuthValue, err)
	}
	creds.authValue = strings.TrimSpace(string(b))

	// Classified before any follow up prompt, so a mistyped value fails
	// without asking for answers that would be thrown away.
	creds.authType, err = determineAuthType(creds.authValue)
	if err != nil {
		return credentials{}, fmt.Errorf(errFmtDetectAuthType, err)
	}

	answers := bufio.NewReader(in)
	ask := func(prompt string) string {
		fmt.Fprint(out, prompt)
		line, _ := answers.ReadString('\n')
		return strings.TrimSpace(line)
	}
	switch {
	case creds.authType == authTypeAPIKey && creds.email == "":
		creds.email = ask(promptEmailAddress)
	case strings.HasPrefix(creds.authValue, accountAPITokenPrefix) && creds.ownerAccountID == "":
		creds.ownerAccountID = ask(promptOwnerAccountID)
	}
	return creds, nil
}

// generatePolicy builds the policies for a predefined template. Optional
// accountIDs and zoneIDs narrow the resources the policies apply to:
//
//	accountIDs  zoneIDs  account policy     zone policy
//	----------  -------  -----------------  ------------------------------
//	-           -        all accounts       all zones
//	set         -        listed accounts    all zones in listed accounts
//	-           set      (omitted)          listed zones
//	set         set      listed accounts    listed zones
//
// Restricting to zones alone omits the account policy entirely so the token
// doesn't quietly retain account-wide permissions across every account.
//
// With an ownerAccountID the policies are for an account API token, which can
// only reach its own account and has no user: "all accounts" becomes the
// owner, and zones nest under it.
func generatePolicy(ctx context.Context, client *cloudflare.Client, policyType, ownerAccountID string, accountIDs, zoneIDs []string) ([]policy, error) {
	groups, err := listPermissionGroups(ctx, client, ownerAccountID)
	if err != nil {
		return nil, fmt.Errorf(errFmtFetchPermissionGroups, err)
	}
	accountGroups := groups[permissionScopeAccount]
	zoneGroups := groups[permissionScopeZone]
	userGroups := groups[permissionScopeUser]

	switch policyType {
	case policyTemplateReadOnly:
		accountGroups = filterReadGroups(accountGroups)
		zoneGroups = filterReadGroups(zoneGroups)
		userGroups = filterReadGroups(userGroups)
	case policyTemplateWriteEverything:
		// Cloudflare refuses POST /user/tokens when the new token could manage
		// other tokens ("sub-token is not allowed to have permissions to
		// manage other tokens", code 1001), whatever the scope. That covers
		// "API Tokens Write" in the User bucket and "Account API Tokens Write"
		// in the Account bucket; the matching Read groups are delegable, and
		// the read-only template has always included "API Tokens Read".
		accountGroups = filterAPITokensGroups(accountGroups)
		userGroups = filterAPITokensGroups(userGroups)
	default:
		return nil, fmt.Errorf(errFmtUnknownPolicyTemplate, policyType)
	}

	emitAccountPolicy := len(accountIDs) > 0 || len(zoneIDs) == 0
	emitUserPolicy := ownerAccountID == ""
	if (emitAccountPolicy && len(accountGroups) == 0) || len(zoneGroups) == 0 || (emitUserPolicy && len(userGroups) == 0) {
		return nil, fmt.Errorf(errFmtEmptyPolicyBucket, policyType, len(accountGroups), len(zoneGroups), len(userGroups))
	}
	if ownerAccountID != "" && len(accountIDs) == 0 {
		accountIDs = []string{ownerAccountID}
	}

	var policies []policy
	if emitAccountPolicy {
		policies = append(policies, policy{
			Effect:           policyEffectAllow,
			Resources:        accountResources(accountIDs),
			PermissionGroups: accountGroups,
		})
	}
	policies = append(policies, policy{
		Effect:           policyEffectAllow,
		Resources:        zoneResources(accountIDs, zoneIDs),
		PermissionGroups: zoneGroups,
	})
	if !emitUserPolicy {
		return policies, nil
	}

	// User resources can only name the user creating the token, so the
	// credential being added must be able to read its own user.
	userDetails, err := client.User.Get(ctx)
	if err != nil {
		return nil, fmt.Errorf(errFmtUserFetchForPolicy, err)
	}
	return append(policies, policy{
		Effect:           policyEffectAllow,
		Resources:        map[string]interface{}{policyResourceUserPrefix + userDetails.ID: "*"},
		PermissionGroups: userGroups,
	}), nil
}

func accountResources(accountIDs []string) map[string]interface{} {
	if len(accountIDs) == 0 {
		return map[string]interface{}{policyResourceAllAccounts: "*"}
	}
	resources := make(map[string]interface{}, len(accountIDs))
	for _, id := range accountIDs {
		resources[policyResourceAccountPrefix+id] = "*"
	}
	return resources
}

func zoneResources(accountIDs, zoneIDs []string) map[string]interface{} {
	switch {
	case len(zoneIDs) > 0:
		resources := make(map[string]interface{}, len(zoneIDs))
		for _, id := range zoneIDs {
			resources[policyResourceZonePrefix+id] = "*"
		}
		return resources
	case len(accountIDs) > 0:
		resources := make(map[string]interface{}, len(accountIDs))
		for _, id := range accountIDs {
			resources[policyResourceAccountPrefix+id] = map[string]interface{}{policyResourceAllZones: "*"}
		}
		return resources
	default:
		return map[string]interface{}{policyResourceAllZones: "*"}
	}
}

func filterReadGroups(groups []permissionGroup) []permissionGroup {
	var out []permissionGroup
	for _, g := range groups {
		if isReadGroup(g) {
			out = append(out, g)
		}
	}
	return out
}

// filterAPITokensGroups drops the groups that grant managing API tokens.
func filterAPITokensGroups(groups []permissionGroup) []permissionGroup {
	var out []permissionGroup
	for _, g := range groups {
		if strings.Contains(g.Name, "API Tokens") && !isReadGroup(g) {
			continue
		}
		out = append(out, g)
	}
	return out
}

// isReadGroup reports whether a permission group only grants reads. The API
// describes groups by name alone. Every published group with "Read" as a word
// in its name is read-only; the few read-only groups named otherwise, such as
// "Security Center Insights", are left out of the read-only template.
func isReadGroup(g permissionGroup) bool {
	return slices.Contains(strings.Fields(g.Name), "Read")
}
