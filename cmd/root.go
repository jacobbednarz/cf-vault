package cmd

import (
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "cf-vault",
	Short: "",
	Long:  "Manage your Cloudflare credentials, securely",
	Run:   func(cmd *cobra.Command, args []string) {},
}

// Execute is the main entrypoint for the CLI.
func Execute() error {
	return rootCmd.Execute()
}
