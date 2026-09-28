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
	"github.com/cloudflare/cloudflare-go/v6/user"
	log "github.com/sirupsen/logrus"
	"golang.org/x/term"

	"github.com/99designs/keyring"
	"github.com/spf13/cobra"

	"github.com/pelletier/go-toml"
)

type tomlConfig struct {
	Profiles map[string]profile `toml:"profiles"`
}

type profile struct {
	Email           string   `toml:"email"`
	AuthType        string   `toml:"auth_type"`
	SessionDuration string   `toml:"session_duration,omitempty"`
	SecretBackend   string   `toml:"secret_backend,omitempty"`
	Policies        []policy `toml:"policies,omitempty"`
}

type policy struct {
	Effect           string                 `toml:"effect"`
	ID               string                 `toml:"id,omitempty"`
	PermissionGroups []permissionGroup      `toml:"permission_groups"`
	Resources        map[string]interface{} `toml:"resources"`
}

type permissionGroup struct {
	ID   string `toml:"id"`
	Name string `toml:"name,omitempty"`
}

var addCmd = &cobra.Command{
	Use:   "add [profile]",
	Short: "Add a new profile to your configuration and keychain",
	Long:  "",
	Example: `
  Add a new profile (you will be prompted for credentials)

    $ cf-vault add example-profile

  Add a read-only short lived token profile restricted to a single account

    $ cf-vault add example-profile --profile-template read-only --session-duration 15m --account-id 01a7362d577a6c3019a474fd6f485823

  Add a profile without prompting, reading an API token from stdin

    $ printf '%s' "$TOKEN" | cf-vault add example-profile --authentication-value-stdin

  Add a profile without prompting, reading a global API key from the environment

    $ CF_VAULT_AUTH_VALUE="$API_KEY" cf-vault add example-profile --email jacob@example.com
`,
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) < 1 {
			return errProfileArgRequired
		}
		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {
		profileName := strings.TrimSpace(args[0])
		if err := validateProfileName(profileName); err != nil {
			log.Fatal(err)
		}
		sessionDuration, _ := cmd.Flags().GetString(flagSessionDuration)
		profileTemplate, _ := cmd.Flags().GetString(flagProfileTemplate)
		accountIDs, _ := cmd.Flags().GetStringSlice(flagAccountID)
		zoneIDs, _ := cmd.Flags().GetStringSlice(flagZoneID)
		useSecureEnclave, _ := cmd.Flags().GetBool(flagSecureEnclave)
		useYubikey, _ := cmd.Flags().GetBool(flagYubikey)
		emailAddress, _ := cmd.Flags().GetString(flagEmail)
		authValueFromStdin, _ := cmd.Flags().GetBool(flagAuthValueStdin)
		force, _ := cmd.Flags().GetBool(flagForce)

		if err := validatePolicyTemplate(profileTemplate); err != nil {
			log.Fatal(err)
		}

		if profileTemplate == "" && (len(accountIDs) > 0 || len(zoneIDs) > 0) {
			log.Fatal(errResourceIDsNeedTemplate)
		}
		if err := validateResourceIDs("account", accountIDs); err != nil {
			log.Fatal(err)
		}
		if err := validateResourceIDs("zone", zoneIDs); err != nil {
			log.Fatal(err)
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
			log.Fatal(err)
		}
		configPath := filepath.Join(configDir, configFileName)

		existingConfigFileContents, err := os.ReadFile(configPath)
		if err != nil && !os.IsNotExist(err) {
			log.Fatal(err)
		}

		// A config that fails to parse must stop here: carrying on with an empty
		// profile map would pass the existence check below and then truncate the
		// file, deleting every profile in it.
		tomlConfigStruct := tomlConfig{}
		if err := toml.Unmarshal(existingConfigFileContents, &tomlConfigStruct); err != nil {
			log.Fatalf(errFmtParseConfigFile, configPath, err)
		}

		// If this is the first profile, initialise the map.
		if len(tomlConfigStruct.Profiles) == 0 {
			tomlConfigStruct.Profiles = make(map[string]profile)
		}

		// Checked before reading any credentials so an accidental overwrite
		// fails without the user entering (or piping) a secret for nothing.
		if _, exists := tomlConfigStruct.Profiles[profileName]; exists && !force {
			log.Fatalf(errFmtProfileExists, profileName, configPath)
		}

		emailAddress, authValue, err := readCredentials(emailAddress, authValueFromStdin)
		if err != nil {
			log.Fatalf(errFmtReadAuthValue, err)
		}

		authType, err := determineAuthType(authValue)
		if err != nil {
			log.Fatalf(errFmtDetectAuthType, err)
		}

		// Global API keys authenticate with the email alongside the key; API
		// tokens carry the identity themselves.
		if authType == authTypeAPIKey && emailAddress == "" {
			log.Fatal(errEmailRequiredForAPIKey)
		}

		os.MkdirAll(configDir, 0700)

		newProfile := profile{
			Email:           emailAddress,
			AuthType:        authType,
			SessionDuration: sessionDuration,
			SecretBackend:   secretBackend,
		}

		if profileTemplate != "" {
			cfClient := newClient(authValue, authType, emailAddress)

			// The policies require that one of the resources is the current user.
			// This leads to a potential chicken/egg scenario where the user doesn't
			// valid credentials but needs them to generate the resources. We
			// intentionally spit out `Debug` and `Fatal` messages here to show the
			// original error *and* the friendly version of how to resolve it.
			userDetails, err := cfClient.User.Get(context.Background())
			if err != nil {
				log.Debug(err)
				log.Fatal(errMsgUserFetchForPolicy)
			}

			generatedPolicy, err := generatePolicy(context.Background(), cfClient, profileTemplate, userDetails.ID, accountIDs, zoneIDs)
			if err != nil {
				log.Fatal(err)
			}
			newProfile.Policies = generatedPolicy
		}

		log.Debugf("new profile: %+v", newProfile)

		// Persist the credential first — if storage fails we don't want an
		// orphaned profile entry in config.toml pointing at nothing.
		var successMessage string
		switch secretBackend {
		case secretBackendAgeSE, secretBackendAgeYubikey:
			recipient, err := ensureAgeIdentity(configDir, secretBackend)
			if err != nil {
				log.Fatal(err)
			}
			if err := encryptWithAge(recipient, ageSecretPath(configDir, profileName), []byte(authValue)); err != nil {
				log.Fatal(err)
			}
			if secretBackend == secretBackendAgeSE {
				successMessage = msgSuccessSecureEnclave
			} else {
				successMessage = msgSuccessYubikey
			}
		default:
			ring, err := openKeyring()
			if err != nil {
				log.Fatalf(errFmtOpenKeyring, err)
			}
			if err := ring.Set(keyring.Item{
				Key:  fmt.Sprintf("%s-%s", profileName, authType),
				Data: []byte(authValue),
			}); err != nil {
				log.Fatalf(errFmtAddKeyringItem, err)
			}
			successMessage = msgSuccessKeyring
		}

		tomlConfigStruct.Profiles[profileName] = newProfile
		configFile, err := os.OpenFile(configPath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0700)
		if err != nil {
			log.Fatalf(errFmtOpenConfigFile, configPath)
		}
		defer configFile.Close()
		if err := toml.NewEncoder(configFile).Encode(tomlConfigStruct); err != nil {
			log.Fatal(err)
		}

		fmt.Println(successMessage)
	},
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

// readCredentials resolves the email address and authentication value for a
// new profile. The authentication value comes from the first available of:
//
//  1. stdin, when `--authentication-value-stdin` is set
//  2. the CF_VAULT_AUTH_VALUE environment variable
//  3. an interactive prompt, along with the email if `--email` wasn't passed
//
// The non-interactive sources never prompt: without a terminal there is nobody
// to answer, and a prompt reading from piped stdin would consume the secret.
func readCredentials(emailAddress string, fromStdin bool) (string, string, error) {
	if fromStdin {
		b, err := io.ReadAll(os.Stdin)
		if err != nil {
			return "", "", err
		}
		return emailAddress, strings.TrimSpace(string(b)), nil
	}

	if authValue, ok := os.LookupEnv(envAuthValue); ok {
		return emailAddress, strings.TrimSpace(authValue), nil
	}

	stdinFd := int(os.Stdin.Fd())
	if !term.IsTerminal(stdinFd) {
		return "", "", errAuthValueSourceRequired
	}

	if emailAddress == "" {
		fmt.Print(promptEmailAddress)
		line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		emailAddress = strings.TrimSpace(line)
	}

	fmt.Print(promptAuthValue)
	b, err := term.ReadPassword(stdinFd)
	fmt.Println()
	if err != nil {
		return "", "", err
	}
	return emailAddress, strings.TrimSpace(string(b)), nil
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
func generatePolicy(ctx context.Context, client *cloudflare.Client, policyType, userID string, accountIDs, zoneIDs []string) ([]policy, error) {
	page, err := client.User.Tokens.PermissionGroups.List(ctx, user.TokenPermissionGroupListParams{})
	if err != nil {
		return nil, fmt.Errorf(errFmtFetchPermissionGroups, err)
	}

	var accountGroups, zoneGroups, userGroups []permissionGroup
	for _, g := range page.Result {
		for _, scope := range g.Scopes {
			pg := permissionGroup{ID: g.ID, Name: g.Name}
			switch scope {
			case user.TokenPermissionGroupListResponseScopeComCloudflareAPIAccountZone:
				zoneGroups = append(zoneGroups, pg)
			case user.TokenPermissionGroupListResponseScopeComCloudflareAPIAccount:
				accountGroups = append(accountGroups, pg)
			case user.TokenPermissionGroupListResponseScopeComCloudflareAPIUser:
				userGroups = append(userGroups, pg)
			}
		}
	}

	switch policyType {
	case policyTemplateReadOnly:
		accountGroups = filterReadGroups(accountGroups)
		zoneGroups = filterReadGroups(zoneGroups)
		userGroups = filterReadGroups(userGroups)
	case policyTemplateWriteEverything:
		// Cloudflare refuses POST /user/tokens when the new token would carry
		// token-management permissions of its own ("sub-token is not allowed to
		// have permissions to manage other tokens", code 1001). The rule applies
		// regardless of scope, so filter both the User bucket ("API Tokens
		// Read/Write") and the Account bucket ("Account API Tokens Read/Write").
		accountGroups = filterAPITokensGroups(accountGroups)
		userGroups = filterAPITokensGroups(userGroups)
	default:
		return nil, fmt.Errorf(errFmtUnknownPolicyTemplate, policyType)
	}

	emitAccountPolicy := len(accountIDs) > 0 || len(zoneIDs) == 0
	if (emitAccountPolicy && len(accountGroups) == 0) || len(zoneGroups) == 0 || len(userGroups) == 0 {
		return nil, fmt.Errorf(errFmtEmptyPolicyBucket, policyType, len(accountGroups), len(zoneGroups), len(userGroups))
	}

	var policies []policy
	if emitAccountPolicy {
		policies = append(policies, policy{
			Effect:           policyEffectAllow,
			Resources:        accountResources(accountIDs),
			PermissionGroups: accountGroups,
		})
	}
	return append(policies,
		policy{
			Effect:           policyEffectAllow,
			Resources:        zoneResources(accountIDs, zoneIDs),
			PermissionGroups: zoneGroups,
		},
		policy{
			Effect:           policyEffectAllow,
			Resources:        map[string]interface{}{policyResourceUserPrefix + userID: "*"},
			PermissionGroups: userGroups,
		},
	), nil
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
		if strings.Contains(g.Name, "Read") {
			out = append(out, g)
		}
	}
	return out
}

func filterAPITokensGroups(groups []permissionGroup) []permissionGroup {
	var out []permissionGroup
	for _, g := range groups {
		if strings.Contains(g.Name, "API Tokens") {
			continue
		}
		out = append(out, g)
	}
	return out
}
