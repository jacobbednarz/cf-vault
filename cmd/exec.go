package cmd

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/99designs/keyring"
	"github.com/mitchellh/go-homedir"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"gopkg.in/ini.v1"
)

var execCmd = &cobra.Command{
	Use:   "exec [profile]",
	Short: "Execute a command with Cloudflare credentials populated",
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
		profileName := args[0]
		log.Debug("using profile: ", profileName)

		home, err := homedir.Dir()
		if err != nil {
			log.Fatal("unable to find home directory: ", err)
		}
		cfg, err := ini.Load(home + defaultFullConfigPath)
		profileSection, err := cfg.GetSection("profile " + profileName)
		if err != nil {
			log.Fatal("unable to create profile section: ", err)
		}

		if profileSection.Key("email").String() == "" {
			log.Fatal(fmt.Sprintf("no profile matching %q found in the configuration file at %s", profileName, defaultFullConfigPath))
		}

		ring, _ := keyring.Open(keyring.Config{
			FileDir:     "~/.cf-vault/keys/",
			ServiceName: projectName,
		})

		i, _ := ring.Get(fmt.Sprintf("%s-%s", profileName, profileSection.Key("auth_type").String()))

		fmt.Printf("%v", string(i.Data))

		log.Debug("environment is populated with credentials")

		command := exec.Command(args[1])
		command.Env = append(os.Environ(),
			fmt.Sprintf("CLOUDFLARE_EMAIL=%s", profileSection.Key("email").String()),
			fmt.Sprintf("CLOUDFLARE_%s=%s", strings.ToUpper(profileSection.Key("auth_type").String()), string(i.Data)),
		)
		commandOutput := &bytes.Buffer{}
		command.Stdout = commandOutput
		err = command.Run()
		if err != nil {
			os.Stderr.WriteString(err.Error())
		}
		fmt.Print(string(commandOutput.Bytes()))
	},
}
