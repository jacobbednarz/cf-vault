package cmd

import (
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	verbose                bool
	projectName            = "cf-vault"
	defaultConfigDirectory = "/." + projectName
	defaultFullConfigPath  = defaultConfigDirectory + "/config"
)

var rootCmd = &cobra.Command{
	Use:  projectName,
	Long: "Manage your Cloudflare credentials, securely",
	PreRun: func(cmd *cobra.Command, args []string) {
		if verbose {
			log.SetLevel(log.DebugLevel)
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
