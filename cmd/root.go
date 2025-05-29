package cmd

import (
	"fmt"
	"os"

	"github.com/99designs/keyring"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var (
	verbose                  bool
	help                     bool
	projectName              = "cf-vault"
	projectNameWithoutHyphen = "cfvault"
	defaultConfigDirectory   = "/." + projectName
	defaultFullConfigPath    = defaultConfigDirectory + "/config.toml"
)

var keyringDefaults = keyring.Config{
	FileDir:                  fmt.Sprintf("~/.%s/keys/", projectName),
	FilePasswordFunc:         fileKeyringPassphrasePrompt,
	ServiceName:              projectName,
	KeychainName:             projectName,
	LibSecretCollectionName:  projectNameWithoutHyphen,
	KWalletAppID:             projectName,
	KWalletFolder:            projectName,
	KeychainTrustApplication: true,
	WinCredPrefix:            projectName,
}

var rootCmd = &cobra.Command{
	Use:  projectName,
	Long: "Manage your Cloudflare credentials, securely.",
	PreRun: func(cmd *cobra.Command, args []string) {
		if verbose {
			logrus.SetLevel(logrus.DebugLevel)
		}

		if len(args) == 0 {
			cmd.Help()
			os.Exit(0)
		}
	},
	Run: func(cmd *cobra.Command, args []string) {},
}

// Get passphrase prompt (copied from https://github.com/99designs/aws-vault)
func fileKeyringPassphrasePrompt(prompt string) (string, error) {
	if password, ok := os.LookupEnv("CF_VAULT_FILE_PASSPHRASE"); ok {
		return password, nil
	}

	fmt.Fprintf(os.Stderr, "%s: ", prompt)
	b, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return "", err
	}
	fmt.Println()
	return string(b), nil
}

func init() {
	logrus.SetLevel(logrus.WarnLevel)
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Increase the verbosity of the output")
	rootCmd.PersistentFlags().BoolVarP(&help, "help", "h", false, "Help for cf-vault")

	var profileTemplate string
	var sessionDuration string
	addCmd.Flags().StringVarP(&profileTemplate, "profile-template", "", "", "Create profile with a predefined permissions and resources template")
	addCmd.Flags().StringVarP(&sessionDuration, "session-duration", "", "", "TTL of short lived tokens requests")

	rootCmd.AddCommand(addCmd)
	rootCmd.AddCommand(listCmd)
	rootCmd.AddCommand(execCmd)
	rootCmd.AddCommand(versionCmd)
}

// Execute is the main entrypoint for the CLI.
func Execute() error {
	return rootCmd.Execute()
}
