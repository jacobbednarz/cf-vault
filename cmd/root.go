package cmd

import (
	"fmt"
	"os"

	"github.com/99designs/keyring"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"golang.org/x/term"
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
	// Errors are reported on their own; the full usage text buries them.
	SilenceUsage: true,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		if verbose {
			log.SetLevel(log.DebugLevel)
			keyring.Debug = true
		}
	},
}

// Get passphrase prompt (copied from https://github.com/99designs/aws-vault)
func fileKeyringPassphrasePrompt(prompt string) (string, error) {
	if password, ok := os.LookupEnv(envFilePassphrase); ok {
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
	log.SetLevel(log.WarnLevel)

	rootCmd.PersistentFlags().BoolVarP(&verbose, flagVerbose, "v", false, "increase the verbosity of the output")

	var profileTemplate string
	var sessionDuration string
	var secureEnclave bool
	var yubikey bool
	var accountIDs []string
	var zoneIDs []string
	var ownerAccountID string
	var emailAddress string
	var authValueFromStdin bool
	var force bool
	addCmd.Flags().StringVarP(&profileTemplate, flagProfileTemplate, "", "", "create profile with a predefined permissions and resources template ("+policyTemplateReadOnly+", "+policyTemplateWriteEverything+")")
	addCmd.RegisterFlagCompletionFunc(flagProfileTemplate, cobra.FixedCompletions(policyTemplates, cobra.ShellCompDirectiveNoFileComp))
	addCmd.Flags().StringSliceVarP(&accountIDs, flagAccountID, "", nil, "restrict the --profile-template policies to these account IDs (repeatable)")
	addCmd.Flags().StringSliceVarP(&zoneIDs, flagZoneID, "", nil, "restrict the --profile-template policies to these zone IDs (repeatable)")
	addCmd.Flags().StringVarP(&ownerAccountID, flagOwnerAccountID, "", "", "ID of the account that owns the API token, when adding an account API token rather than a user one; required to create short lived tokens from it")
	addCmd.Flags().StringVarP(&sessionDuration, flagSessionDuration, "", "", "lifetime of the short lived tokens created by exec, such as 15m or 1h; at least "+minSessionDuration.String()+" and rounded down to whole seconds")
	addCmd.MarkFlagsRequiredTogether(flagProfileTemplate, flagSessionDuration)
	addCmd.Flags().BoolVarP(&secureEnclave, flagSecureEnclave, "", false, "store the credential encrypted with age to a Secure Enclave key (requires `age` and `age-plugin-se`); unlocks via Touch ID instead of the keychain password")
	addCmd.Flags().BoolVarP(&yubikey, flagYubikey, "", false, "store the credential encrypted with age to a YubiKey PIV identity (requires `age` and `age-plugin-yubikey`); unlocks via a hardware touch instead of the keychain password")
	addCmd.MarkFlagsMutuallyExclusive(flagSecureEnclave, flagYubikey)
	addCmd.Flags().StringVarP(&emailAddress, flagEmail, "", "", "email address of the account; required for global API keys")
	addCmd.Flags().BoolVarP(&authValueFromStdin, flagAuthValueStdin, "", false, "read the authentication value (API key or API token) from stdin instead of prompting; alternatively set "+envAuthValue)
	addCmd.Flags().BoolVarP(&force, flagForce, "", false, "overwrite the profile if it already exists")

	// Everything after the profile name is the command to run, flags included.
	execCmd.Flags().SetInterspersed(false)

	rootCmd.AddCommand(addCmd)
	rootCmd.AddCommand(listCmd)
	rootCmd.AddCommand(execCmd)
	rootCmd.AddCommand(versionCmd)
}

// Execute is the main entrypoint for the CLI.
func Execute() error {
	return rootCmd.Execute()
}
