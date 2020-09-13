package cmd

import (
	"fmt"
	"runtime"

	"github.com/spf13/cobra"
)

// Rev is set on build time and should follow the semantic version format for
// versioning strings.
var Rev = "0.0.0-dev"

func init() {
	rootCmd.AddCommand(versionCmd)
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version string of cf-vault",
	Long:  "",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("%s %s (%s,%s-%s)", "cf-vault", Rev, runtime.Version(), runtime.Compiler, runtime.GOARCH)
	},
}
