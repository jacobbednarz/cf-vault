package cmd

import (
	"fmt"
	"os"

	"github.com/99designs/keyring"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh/terminal"
)

var (
	verbose                  bool
	projectName              = "cf-vault"
	projectNameWithoutHyphen = "cfvault"
)

var keyringDefaults = keyring.Config{
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
	Long: "Manage your Cloudflare credentials, securely",
	PreRun: func(cmd *cobra.Command, args []string) {
		if verbose {
			log.SetLevel(log.DebugLevel)
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
	if password, ok := os.LookupEnv(envFilePassphrase); ok {
		return password, nil
	}

	fmt.Fprintf(os.Stderr, "%s: ", prompt)
	b, err := terminal.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return "", err
	}
	fmt.Println()
	return string(b), nil
}

func init() {
	log.SetLevel(log.WarnLevel)

	rootCmd.PersistentFlags().BoolVarP(&verbose, flagVerbose, "v", false, "increase the verbosity of the output")

	var profileTemplate string
	var sessionDuration string
	var secureEnclave bool
	var yubikey bool
	addCmd.Flags().StringVarP(&profileTemplate, flagProfileTemplate, "", "", "create profile with a predefined permissions and resources template")
	addCmd.Flags().StringVarP(&sessionDuration, flagSessionDuration, "", "", "TTL of short lived tokens requests")
	addCmd.Flags().BoolVarP(&secureEnclave, flagSecureEnclave, "", false, "store the credential encrypted with age to a Secure Enclave key (requires `age` and `age-plugin-se`); unlocks via Touch ID instead of the keychain password")
	addCmd.Flags().BoolVarP(&yubikey, flagYubikey, "", false, "store the credential encrypted with age to a YubiKey PIV identity (requires `age` and `age-plugin-yubikey`); unlocks via a hardware touch instead of the keychain password")
	addCmd.MarkFlagsMutuallyExclusive(flagSecureEnclave, flagYubikey)

	rootCmd.AddCommand(addCmd)
	rootCmd.AddCommand(listCmd)
	rootCmd.AddCommand(execCmd)
	rootCmd.AddCommand(versionCmd)
}

// Execute is the main entrypoint for the CLI.
func Execute() error {
	return rootCmd.Execute()
}
