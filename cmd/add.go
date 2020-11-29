package cmd

import (
	"bufio"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"regexp"
	"strings"

	"github.com/cloudflare/cloudflare-go"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh/terminal"

	"github.com/99designs/keyring"
	"github.com/mitchellh/go-homedir"
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
		byteAuthValue, err := terminal.ReadPassword(0)
		if err != nil {
			log.Fatal("unable to read authentication value: ", err)
		}
		authValue := string(byteAuthValue)
		fmt.Println()

		authType, err := determineAuthType(strings.TrimSpace(authValue))
		if err != nil {
			log.Fatal("failed to detect authentication type: ", err)
		}

		home, err := homedir.Dir()
		if err != nil {
			log.Fatal("unable to find home directory: ", err)
		}

		os.MkdirAll(home+defaultConfigDirectory, 0700)
		if _, err := os.Stat(home + defaultFullConfigPath); os.IsNotExist(err) {
			file, err := os.Create(home + defaultFullConfigPath)
			if err != nil {
				log.Fatal(err)
			}
			defer file.Close()
		}

		existingConfigFileContents, err := ioutil.ReadFile(home + defaultFullConfigPath)
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

		var api *cloudflare.API
		if authType == "api_token" {
			api, err = cloudflare.NewWithAPIToken(authValue)
			if err != nil {
				log.Fatal(err)
			}
		} else {
			api, err = cloudflare.New(authValue, emailAddress)
			if err != nil {
				log.Fatal(err)
			}
		}

		if profileTemplate != "" {
			// The policies require that one of the resources is the current user.
			// This leads to a potential chicken/egg scenario where the user doesn't
			// valid credentials but needs them to generate the resources. We
			// intentionally spit out `Debug` and `Fatal` messages here to show the
			// original error *and* the friendly version of how to resolve it.
			userDetails, err := api.UserDetails()
			if err != nil {
				log.Debug(err)
				log.Fatal("failed to fetch user ID from the Cloudflare API which is required to generate the predefined short lived token policies. If you are using API tokens, please allow the permission to access your user details and try again.")
			}

			generatedPolicy, err := generatePolicy(profileTemplate, userDetails.ID)
			if err != nil {
				log.Fatal(err)
			}
			newProfile.Policies = generatedPolicy
		}

		log.Debugf("new profile: %+v", newProfile)
		tomlConfigStruct.Profiles[profileName] = newProfile

		configFile, err := os.OpenFile(home+defaultFullConfigPath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0700)
		if err != nil {
			log.Fatal("failed to open file at ", home+defaultFullConfigPath)
		}
		defer configFile.Close()
		if err := toml.NewEncoder(configFile).Encode(tomlConfigStruct); err != nil {
			log.Fatal(err)
		}

		ring, _ := keyring.Open(keyringDefaults)

		_ = ring.Set(keyring.Item{
			Key:  fmt.Sprintf("%s-%s", profileName, authType),
			Data: []byte(authValue),
		})

		fmt.Println("\nSuccess! Credentials have been set and are now ready for use!")
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

func generatePolicy(policyType, userID string) ([]policy, error) {
	readOnlyPolicy := []policy{
		{
			Effect:    "allow",
			Resources: map[string]interface{}{"com.cloudflare.api.account.*": "*"},
			PermissionGroups: []permissionGroup{
				{ID: "7ea222f6d5064cfa89ea366d7c1fee89"},
				{ID: "b05b28e839c54467a7d6cba5d3abb5a3"},
				{ID: "4f3196a5c95747b6ad82e34e1d0a694f"},
				{ID: "0f4841f80adb4bada5a09493300e7f8d"},
				{ID: "26bc23f853634eb4bff59983b9064fde"},
				{ID: "91f7ce32fa614d73b7e1fc8f0e78582b"},
				{ID: "b89a480218d04ceb98b4fe57ca29dc1f"},
				{ID: "de7a688cc47d43bd9ea700b467a09c96"},
				{ID: "4f1071168de8466e9808de86febfc516"},
				{ID: "c1fde68c7bcc44588cbb6ddbc16d6480"},
				{ID: "efea2ab8357b47888938f101ae5e053f"},
				{ID: "7cf72faf220841aabcfdfab81c43c4f6"},
				{ID: "5f48a472240a4b489a21d43bd19a06e1"},
				{ID: "e763fae6ee95443b8f56f19213c5f2a5"},
				{ID: "9d24387c6e8544e2bc4024a03991339f"},
				{ID: "6a315a56f18441e59ed03352369ae956"},
				{ID: "58abbad6d2ce40abb2594fbe932a2e0e"},
				{ID: "de21485a24744b76a004aa153898f7fe"},
				{ID: "3f376c8e6f764a938b848bd01c8995c4"},
				{ID: "8b47d2786a534c08a1f94ee8f9f599ef"},
				{ID: "1a71c399035b4950a1bd1466bbe4f420"},
				{ID: "05880cd1bdc24d8bae0be2136972816b"},
			},
		},
		{
			Effect:    "allow",
			Resources: map[string]interface{}{"com.cloudflare.api.account.zone.*": "*"},
			PermissionGroups: []permissionGroup{
				{ID: "eb258a38ea634c86a0c89da6b27cb6b6"},
				{ID: "9c88f9c5bce24ce7af9a958ba9c504db"},
				{ID: "82e64a83756745bbbb1c9c2701bf816b"},
				{ID: "4ec32dfcb35641c5bb32d5ef1ab963b4"},
				{ID: "e9a975f628014f1d85b723993116f7d5"},
				{ID: "c4a30cd58c5d42619c86a3c36c441e2d"},
				{ID: "b415b70a4fd1412886f164451f20405c"},
				{ID: "7b7216b327b04b8fbc8f524e1f9b7531"},
				{ID: "2072033d694d415a936eaeb94e6405b8"},
				{ID: "c8fed203ed3043cba015a93ad1616f1f"},
				{ID: "517b21aee92c4d89936c976ba6e4be55"},
			},
		},
		{
			Effect:    "allow",
			Resources: map[string]interface{}{"com.cloudflare.api.user." + userID: "*"},
			PermissionGroups: []permissionGroup{
				{ID: "3518d0f75557482e952c6762d3e64903"},
				{ID: "8acbe5bb0d54464ab867149d7f7cf8ac"},
			},
		},
	}

	writeEverythingPolicy := []policy{
		{
			Effect:    "allow",
			Resources: map[string]interface{}{"com.cloudflare.api.account.*": "*"},
			PermissionGroups: []permissionGroup{
				{ID: "1e13c5124ca64b72b1969a67e8829049"},
				{ID: "b05b28e839c54467a7d6cba5d3abb5a3"},
				{ID: "29d3afbfd4054af9accdd1118815ed05"},
				{ID: "2fc1072ee6b743828db668fcb3f9dee7"},
				{ID: "bfe0d8686a584fa680f4c53b5eb0de6d"},
				{ID: "a1c0fec57cf94af79479a6d827fa518c"},
				{ID: "b89a480218d04ceb98b4fe57ca29dc1f"},
				{ID: "a416acf9ef5a4af19fb11ed3b96b1fe6"},
				{ID: "2edbf20661fd4661b0fe10e9e12f485c"},
				{ID: "1af1fa2adc104452b74a9a3364202f20"},
				{ID: "c07321b023e944ff818fec44d8203567"},
				{ID: "6c80e02421494afc9ae14414ed442632"},
				{ID: "da6d2d6f2ec8442eaadda60d13f42bca"},
				{ID: "2ae23e4939d54074b7d252d27ce75a77"},
				{ID: "d2a1802cc9a34e30852f8b33869b2f3c"},
				{ID: "96163bd1b0784f62b3e44ed8c2ab1eb6"},
				{ID: "61ddc58f1da14f95b33b41213360cbeb"},
				{ID: "b33f02c6f7284e05a6f20741c0bb0567"},
				{ID: "f7f0eda5697f475c90846e879bab8666"},
				{ID: "e086da7e2179491d91ee5f35b3ca210a"},
				{ID: "05880cd1bdc24d8bae0be2136972816b"},
			},
		},
		{
			Effect:    "allow",
			Resources: map[string]interface{}{"com.cloudflare.api.account.zone.*": "*"},
			PermissionGroups: []permissionGroup{
				{ID: "959972745952452f8be2452be8cbb9f2"},
				{ID: "9c88f9c5bce24ce7af9a958ba9c504db"},
				{ID: "094547ab6e77498c8c4dfa87fadd5c51"},
				{ID: "e17beae8b8cb423a99b1730f21238bed"},
				{ID: "4755a26eedb94da69e1066d98aa820be"},
				{ID: "43137f8d07884d3198dc0ee77ca6e79b"},
				{ID: "6d7f2f5f5b1d4a0e9081fdc98d432fd1"},
				{ID: "3e0b5820118e47f3922f7c989e673882"},
				{ID: "ed07f6c337da4195b4e72a1fb2c6bcae"},
				{ID: "c03055bc037c4ea9afb9a9f104b7b721"},
				{ID: "28f4b596e7d643029c524985477ae49a"},
				{ID: "e6d2666161e84845a636613608cee8d5"},
				{ID: "3030687196b94b638145a3953da2b699"},
			},
		},
		{
			Effect:    "allow",
			Resources: map[string]interface{}{"com.cloudflare.api.user." + userID: "*"},
			PermissionGroups: []permissionGroup{
				{ID: "9201bc6f42d440968aaab0c6f17ebb1d"},
				{ID: "55a5e17cc99e4a3fa1f3432d262f2e55"},
			},
		},
	}

	switch policyType {
	case "write-everything":
		log.Debug("configuring a write-everything template")
		return writeEverythingPolicy, nil
	case "read-only":
		log.Debug("configuring a read-only template")
		return readOnlyPolicy, nil
	}

	return nil, fmt.Errorf("unable to generate policy for %q", policyType)
}
