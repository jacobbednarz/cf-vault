package cmd

import (
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(execCmd)
}

var execCmd = &cobra.Command{
	Use:   "exec",
	Short: "Execute a command with Cloudflare credentials populated",
	Long:  "",
	Run:   func(cmd *cobra.Command, args []string) {},
}
