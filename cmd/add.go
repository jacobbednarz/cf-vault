package cmd

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
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
`,
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) < 1 {
			return errors.New("requires a profile argument")
		}
		return nil
	},
	PreRun: func(cmd *cobra.Command, args []string) {
		if verbose {
			log.SetLevel(log.DebugLevel)
			keyring.Debug = true
		}
	},
	Run: func(cmd *cobra.Command, args []string) {
		profileName := strings.TrimSpace(args[0])
		if err := validateProfileName(profileName); err != nil {
			log.Fatal(err)
		}
		sessionDuration, _ := cmd.Flags().GetString("session-duration")
		profileTemplate, _ := cmd.Flags().GetString("profile-template")
		useSecureEnclave, _ := cmd.Flags().GetBool("secure-enclave")
		useYubikey, _ := cmd.Flags().GetBool("yubikey")

		var secretBackend string
		switch {
		case useSecureEnclave:
			secretBackend = secretBackendAgeSE
		case useYubikey:
			secretBackend = secretBackendAgeYubikey
		}

		reader := bufio.NewReader(os.Stdin)
		fmt.Print("Email address: ")
		emailAddress, _ := reader.ReadString('\n')
		emailAddress = strings.TrimSpace(emailAddress)

		fmt.Print("Authentication value (API key or API token): ")
		byteAuthValue, err := term.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			log.Fatal("unable to read authentication value: ", err)
		}
		authValue := string(byteAuthValue)
		fmt.Println()

		authType, err := determineAuthType(strings.TrimSpace(authValue))
		if err != nil {
			log.Fatal("failed to detect authentication type: ", err)
		}

		configDir, err := resolveConfigDir()
		if err != nil {
			log.Fatal(err)
		}
		configPath := filepath.Join(configDir, "config.toml")

		os.MkdirAll(configDir, 0700)
		if _, err := os.Stat(configPath); os.IsNotExist(err) {
			file, err := os.Create(configPath)
			if err != nil {
				log.Fatal(err)
			}
			defer file.Close()
		}

		existingConfigFileContents, err := os.ReadFile(configPath)
		if err != nil {
			log.Fatal(err)
		}

		tomlConfigStruct := tomlConfig{}
		toml.Unmarshal(existingConfigFileContents, &tomlConfigStruct)

		// If this is the first profile, initialise the map.
		if len(tomlConfigStruct.Profiles) == 0 {
			tomlConfigStruct.Profiles = make(map[string]profile)
		}

		newProfile := profile{
			Email:    emailAddress,
			AuthType: authType,
		}

		if sessionDuration != "" {
			newProfile.SessionDuration = sessionDuration
		} else {
			log.Debug("session-duration was not set, not using short lived tokens")
		}

		if secretBackend != "" {
			newProfile.SecretBackend = secretBackend
		}

		var cfClient *cloudflare.Client
		if profileTemplate != "" {
			cfClient = newClient(authValue, authType, emailAddress)
		}

		if profileTemplate != "" {
			// The policies require that one of the resources is the current user.
			// This leads to a potential chicken/egg scenario where the user doesn't
			// valid credentials but needs them to generate the resources. We
			// intentionally spit out `Debug` and `Fatal` messages here to show the
			// original error *and* the friendly version of how to resolve it.
			userDetails, err := cfClient.User.Get(context.Background())
			if err != nil {
				log.Debug(err)
				log.Fatal("failed to fetch user ID from the Cloudflare API which is required to generate the predefined short lived token policies. If you are using API tokens, please allow the permission to access your user details and try again.")
			}

			generatedPolicy, err := generatePolicy(context.Background(), cfClient, profileTemplate, userDetails.ID)
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
				successMessage = "\nSuccess! Credentials encrypted to the Secure Enclave and are now ready for use!"
			} else {
				successMessage = "\nSuccess! Credentials encrypted to a YubiKey identity and are now ready for use!"
			}
		default:
			ring, err := openKeyring()
			if err != nil {
				log.Fatalf("failed to open keyring backend: %s", strings.ToLower(err.Error()))
			}
			if err := ring.Set(keyring.Item{
				Key:  fmt.Sprintf("%s-%s", profileName, authType),
				Data: []byte(authValue),
			}); err != nil {
				log.Fatal("Error adding credentials to keyring: ", err)
			}
			successMessage = "\nSuccess! Credentials have been set and are now ready for use!"
		}

		tomlConfigStruct.Profiles[profileName] = newProfile
		configFile, err := os.OpenFile(configPath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0700)
		if err != nil {
			log.Fatal("failed to open file at ", configPath)
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
		return errors.New("profile name must not be empty")
	}
	if !profileNameRE.MatchString(name) {
		return fmt.Errorf("profile name %q is invalid; use only letters, digits, `.`, `_`, `-`, and do not start with `.`", name)
	}
	return nil
}

func determineAuthType(s string) (string, error) {
	if apiTokenMatch, _ := regexp.MatchString("[A-Za-z0-9-_]{40}", s); apiTokenMatch {
		log.Debug("API token detected")
		return "api_token", nil
	} else if apiKeyMatch, _ := regexp.MatchString("[0-9a-f]{37}", s); apiKeyMatch {
		log.Debug("API key detected")
		return "api_key", nil
	} else {
		return "", errors.New("invalid API token or API key format")
	}
}

func generatePolicy(ctx context.Context, client *cloudflare.Client, policyType, userID string) ([]policy, error) {
	page, err := client.User.Tokens.PermissionGroups.List(ctx, user.TokenPermissionGroupListParams{})
	if err != nil {
		return nil, fmt.Errorf("failed to fetch permission groups: %w", err)
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
	case "read-only":
		accountGroups = filterReadGroups(accountGroups)
		zoneGroups = filterReadGroups(zoneGroups)
		userGroups = filterReadGroups(userGroups)
	case "write-everything":
		// Cloudflare refuses POST /user/tokens when the new token would carry
		// token-management permissions of its own ("sub-token is not allowed to
		// have permissions to manage other tokens", code 1001). The rule applies
		// regardless of scope, so filter both the User bucket ("API Tokens
		// Read/Write") and the Account bucket ("Account API Tokens Read/Write").
		accountGroups = filterAPITokensGroups(accountGroups)
		userGroups = filterAPITokensGroups(userGroups)
	default:
		return nil, fmt.Errorf("unable to generate policy for %q, valid policy names: [read-only, write-everything]", policyType)
	}

	if len(accountGroups) == 0 || len(zoneGroups) == 0 || len(userGroups) == 0 {
		return nil, fmt.Errorf("one or more policy buckets is empty for policy type %q (account=%d, zone=%d, user=%d); check API permissions", policyType, len(accountGroups), len(zoneGroups), len(userGroups))
	}

	return []policy{
		{
			Effect:           "allow",
			Resources:        map[string]interface{}{"com.cloudflare.api.account.*": "*"},
			PermissionGroups: accountGroups,
		},
		{
			Effect:           "allow",
			Resources:        map[string]interface{}{"com.cloudflare.api.account.zone.*": "*"},
			PermissionGroups: zoneGroups,
		},
		{
			Effect:           "allow",
			Resources:        map[string]interface{}{"com.cloudflare.api.user." + userID: "*"},
			PermissionGroups: userGroups,
		},
	}, nil
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
