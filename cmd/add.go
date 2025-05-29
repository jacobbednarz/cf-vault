package cmd

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"regexp"
	"slices"
	"strings"

	"github.com/cloudflare/cloudflare-go/v4"
	"github.com/cloudflare/cloudflare-go/v4/option"
	"github.com/sirupsen/logrus"
	"golang.org/x/term"

	"github.com/99designs/keyring"
	"github.com/mitchellh/go-homedir"
	"github.com/spf13/cobra"

	"github.com/pelletier/go-toml"
)

var client *cloudflare.Client

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
	Effect           string            `toml:"effect"`
	ID               string            `toml:"id,omitempty"`
	PermissionGroups []permissionGroup `toml:"permission_groups"`
	Resources        map[string]any    `toml:"resources"`
}

type permissionGroup struct {
	ID          string   `toml:"id" json:"id"`
	Name        string   `toml:"name,omitempty" json:"name"`
	Description string   `toml:"-,omitempty" json:"description"`
	Scopes      []string `toml:"-,omitempty" json:"scopes"`
}

// The structs below (response envelopes) can be removed once
// they are present in cloudflare-go.

type userDetailsResponseEnvelope struct {
	Result userDetails `json:"result"`
}

type userDetails struct {
	ID string `json:"id"`
}

type permissionGroupResponseEnvelope struct {
	Result []permissionGroup `json:"result"`
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
			logrus.SetLevel(logrus.DebugLevel)
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
		byteAuthValue, err := term.ReadPassword(0)
		if err != nil {
			logrus.Fatal("unable to read authentication value: ", err)
		}
		authValue := string(byteAuthValue)
		fmt.Println()

		authType, err := determineAuthType(strings.TrimSpace(authValue))
		if err != nil {
			logrus.Fatal("failed to detect authentication type: ", err)
		}

		home, err := homedir.Dir()
		if err != nil {
			logrus.Fatal("unable to find home directory: ", err)
		}

		os.MkdirAll(home+defaultConfigDirectory, 0700)
		if _, err := os.Stat(home + defaultFullConfigPath); os.IsNotExist(err) {
			file, err := os.Create(home + defaultFullConfigPath)
			if err != nil {
				logrus.Fatal(err)
			}
			defer file.Close()
		}

		existingConfigFileContents, err := os.ReadFile(home + defaultFullConfigPath)
		if err != nil {
			logrus.Fatal(err)
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
			logrus.Debug("session-duration was not set, not using short lived tokens")
		}

		if authType == "api_token" {
			client = cloudflare.NewClient(option.WithAPIToken(authValue))
			if err != nil {
				logrus.Fatal(err)
			}
		} else {
			client = cloudflare.NewClient(option.WithAPIKey(authValue), option.WithAPIEmail(emailAddress))
			if err != nil {
				logrus.Fatal(err)
			}
		}

		if profileTemplate != "" {
			var userDetailsResponse *userDetailsResponseEnvelope
			_, err := client.User.Get(context.Background(), option.WithResponseBodyInto(&userDetailsResponse))
			if err != nil {
				// The policies require that one of the resources is the current user.
				// This leads to a potential chicken/egg scenario where the user doesn't
				// valid credentials but needs them to generate the resources. We
				// intentionally spit out `Debug` and `Fatal` messages here to show the
				// original error *and* the friendly version of how to resolve it.
				logrus.Debug(err)
				logrus.Fatal("failed to fetch user ID from the Cloudflare API which is required to generate the predefined short lived token policies. If you are using API tokens, please allow the permission to access your user details and try again.")
			}

			generatedPolicy, err := generatePolicy(profileTemplate, userDetailsResponse.Result.ID)
			if err != nil {
				logrus.Fatal(err)
			}
			newProfile.Policies = generatedPolicy
		}

		logrus.Debugf("new profile: %+v", newProfile)
		tomlConfigStruct.Profiles[profileName] = newProfile

		configFile, err := os.OpenFile(home+defaultFullConfigPath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0700)
		if err != nil {
			logrus.Fatal("failed to open file at ", home+defaultFullConfigPath)
		}
		defer configFile.Close()
		if err := toml.NewEncoder(configFile).Encode(tomlConfigStruct); err != nil {
			logrus.Fatal(err)
		}

		ring, err := keyring.Open(keyringDefaults)
		if err != nil {
			logrus.Fatalf("failed to open keyring backend: %s", strings.ToLower(err.Error()))
		}

		resp := ring.Set(keyring.Item{
			Key:  fmt.Sprintf("%s-%s", profileName, authType),
			Data: []byte(authValue),
		})

		if resp == nil {
			fmt.Println("\nSuccess! Credentials have been set and are now ready for use!")
		} else {
			// error of some sort
			logrus.Fatal("Error adding credentials to keyring: ", resp)
		}
	},
}

func determineAuthType(s string) (string, error) {
	if apiTokenMatch, _ := regexp.MatchString("[A-Za-z0-9-_]{40}", s); apiTokenMatch {
		logrus.Debug("API token detected")
		return "api_token", nil
	} else if apiKeyMatch, _ := regexp.MatchString("[0-9a-f]{37}", s); apiKeyMatch {
		logrus.Debug("API key detected")
		return "api_key", nil
	} else {
		return "", errors.New("invalid API token or API key format")
	}
}

func generatePolicy(policyType, userID string) ([]policy, error) {
	var permissionGroupResponse *permissionGroupResponseEnvelope

	// Using the `client.Get` escape hatch here while IAM work on returning a
	// defined type for the response to avoid casting `unknown` keys.
	_, err := client.User.Tokens.PermissionGroups.List(context.Background(), option.WithResponseBodyInto(&permissionGroupResponse))
	if err != nil {
		logrus.Fatal(err)
	}

	var (
		zoneReads     []permissionGroup
		zoneWrites    []permissionGroup
		accountReads  []permissionGroup
		accountWrites []permissionGroup
		userReads     []permissionGroup
		userWrites    []permissionGroup
	)

	for _, permission := range permissionGroupResponse.Result {
		if permission.Name == "API Tokens Write" {
			continue
		}

		if strings.HasSuffix(permission.Name, "Read") {
			if slices.Contains(permission.Scopes, "com.cloudflare.api.account.zone") {
				zoneReads = append(zoneReads, permission)
			}

			if slices.Contains(permission.Scopes, "com.cloudflare.api.account") {
				accountReads = append(accountReads, permission)
			}

			if slices.Contains(permission.Scopes, "com.cloudflare.api.user") {
				userReads = append(userReads, permission)
			}
		}

		if strings.HasSuffix(permission.Name, "Write") {
			if slices.Contains(permission.Scopes, "com.cloudflare.api.account.zone") {
				zoneWrites = append(zoneWrites, permission)
			}

			if slices.Contains(permission.Scopes, "com.cloudflare.api.account") {
				accountWrites = append(accountWrites, permission)
			}

			if slices.Contains(permission.Scopes, "com.cloudflare.api.user") {
				userWrites = append(userWrites, permission)
			}
		}
	}

	switch policyType {
	case "write-everything":
		logrus.Debug("configuring a write-everything template")
		return []policy{
			{
				Effect:           "allow",
				Resources:        map[string]any{"com.cloudflare.api.account.*": "*"},
				PermissionGroups: accountWrites,
			},
			{
				Effect:           "allow",
				Resources:        map[string]any{"com.cloudflare.api.account.zone.*": "*"},
				PermissionGroups: zoneWrites,
			},
			{
				Effect:           "allow",
				Resources:        map[string]any{"com.cloudflare.api.user." + userID: "*"},
				PermissionGroups: userWrites,
			},
		}, nil
	case "read-only":
		logrus.Debug("configuring a read-only template")
		return []policy{
			{
				Effect:           "allow",
				Resources:        map[string]any{"com.cloudflare.api.account.*": "*"},
				PermissionGroups: accountReads,
			},
			{
				Effect:           "allow",
				Resources:        map[string]any{"com.cloudflare.api.account.zone.*": "*"},
				PermissionGroups: zoneReads,
			},
			{
				Effect:           "allow",
				Resources:        map[string]any{"com.cloudflare.api.user." + userID: "*"},
				PermissionGroups: userReads,
			},
		}, nil
	}

	return nil, fmt.Errorf("unable to generate policy for %q, valid policy names: [read-only, write-everything]", policyType)
}
