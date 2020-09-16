package cmd

import (
	"fmt"
	"runtime"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

// Rev is set on build time and should follow the semantic version format for
// versioning strings.
var Rev = "0.0.0-dev"

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: fmt.Sprintf("Print the version string of %s", projectName),
	Long:  "",
	PreRun: func(cmd *cobra.Command, args []string) {
		if verbose {
			log.SetLevel(log.DebugLevel)
		}
	},
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("%s %s (%s,%s-%s)", projectName, Rev, runtime.Version(), runtime.Compiler, runtime.GOARCH)
	},
}
