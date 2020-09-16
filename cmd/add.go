package cmd

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/99designs/keyring"
	"github.com/mitchellh/go-homedir"
	"github.com/spf13/cobra"
	"gopkg.in/ini.v1"
)

var addCmd = &cobra.Command{
	Use:   "add [profile]",
	Short: "Add a new profile to your configuration and keychain",
	Long:  "",
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

		fmt.Print("Authentication type (api_token or api_key): ")
		authType, _ := reader.ReadString('\n')
		authType = strings.TrimSpace(authType)

		fmt.Print("Authentication value: ")
		authValue, _ := reader.ReadString('\n')
		authValue = strings.TrimSpace(authValue)

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

		cfg, _ := ini.Load(home + defaultFullConfigPath)
		cfg.Section(fmt.Sprintf("profile %s", profileName)).NewKey("email", emailAddress)
		cfg.Section(fmt.Sprintf("profile %s", profileName)).NewKey("auth_type", authType)
		cfg.SaveTo(home + defaultFullConfigPath)

		ring, _ := keyring.Open(keyringDefaults)

		_ = ring.Set(keyring.Item{
			Key:  fmt.Sprintf("%s-%s", profileName, authType),
			Data: []byte(authValue),
		})
	},
}
