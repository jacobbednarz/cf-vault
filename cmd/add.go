package cmd

import (
	"bufio"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"regexp"
	"strings"

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
	Email              string                 `toml:"email"`
	AuthType           string                 `toml:"auth_type"`
	SessionDuration    int                    `toml:"session_duration"`
	Resources          map[string]interface{} `toml:"resources,omitempty"`
	PermissionGroupIDs []string               `toml:"permission_group_ids,omitempty"`
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

		reader := bufio.NewReader(os.Stdin)
		fmt.Print("Email address: ")
		emailAddress, _ := reader.ReadString('\n')
		emailAddress = strings.TrimSpace(emailAddress)

		fmt.Print("Authentication value (API key or API token): ")
		byteAuthValue, err := terminal.ReadPassword(0)
		if err != nil {
			log.Fatalf("\nunable to read authentication value: %s", err)
		}
		authValue := string(byteAuthValue)

		authType, err := determineAuthType(strings.TrimSpace(authValue))
		if err != nil {
			log.Fatalf("failed to detect authentication type: %s", err)
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

		tomlConfigStruct.Profiles[profileName] = profile{
			Email:    emailAddress,
			AuthType: authType,
		}

		configFile, err := os.OpenFile(home+defaultFullConfigPath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0700)
		if err != nil {
			log.Fatalf("failed to open file at %s", home+defaultFullConfigPath)
		}
		defer configFile.Close()
		if err := toml.NewEncoder(configFile).Indentation("").Encode(tomlConfigStruct); err != nil {
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
