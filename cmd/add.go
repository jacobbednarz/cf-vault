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
		sessionDuration, _ := cmd.Flags().GetString("session-duration")
		profileTemplate, _ := cmd.Flags().GetString("profile-template")

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
		tomlConfigStruct.Profiles[profileName] = newProfile

		configFile, err := os.OpenFile(configPath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0700)
		if err != nil {
			log.Fatal("failed to open file at ", configPath)
		}
		defer configFile.Close()
		if err := toml.NewEncoder(configFile).Encode(tomlConfigStruct); err != nil {
			log.Fatal(err)
		}

		ring, err := openKeyring()
		if err != nil {
			log.Fatalf("failed to open keyring backend: %s", strings.ToLower(err.Error()))
		}

		resp := ring.Set(keyring.Item{
			Key:  fmt.Sprintf("%s-%s", profileName, authType),
			Data: []byte(authValue),
		})

		if resp == nil {
			fmt.Println("\nSuccess! Credentials have been set and are now ready for use!")
		} else {
			// error of some sort
			log.Fatal("Error adding credentials to keyring: ", resp)
		}
	},
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

	if policyType == "read-only" {
		accountGroups = filterReadGroups(accountGroups)
		zoneGroups = filterReadGroups(zoneGroups)
		userGroups = filterReadGroups(userGroups)
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
