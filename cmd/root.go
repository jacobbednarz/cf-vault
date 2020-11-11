package cmd

import (
	"fmt"
	"os"

	"github.com/99designs/keyring"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	verbose                  bool
	projectName              = "cf-vault"
	projectNameWithoutHyphen = "cfvault"
	defaultConfigDirectory   = "/." + projectName
	defaultFullConfigPath    = defaultConfigDirectory + "/config.toml"
)

var keyringDefaults = keyring.Config{
	FileDir:                  fmt.Sprintf("~/.%s/keys/", projectName),
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

func init() {
	log.SetLevel(log.WarnLevel)

	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "increase the verbosity of the output")

	rootCmd.AddCommand(addCmd)
	rootCmd.AddCommand(execCmd)
	rootCmd.AddCommand(versionCmd)
}

// Execute is the main entrypoint for the CLI.
func Execute() error {
	return rootCmd.Execute()
}
