package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/olekukonko/tablewriter"
	"github.com/pelletier/go-toml"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List all available profiles",
	Long:  "",
	PreRun: func(cmd *cobra.Command, args []string) {
		if verbose {
			log.SetLevel(log.DebugLevel)
		}
	},
	Run: func(cmd *cobra.Command, args []string) {
		configDir, err := resolveConfigDir()
		if err != nil {
			log.Fatal(err)
		}
		configPath := filepath.Join(configDir, "config.toml")

		configData, err := os.ReadFile(configPath)
		if err != nil {
			log.Fatal(err)
		}

		config := tomlConfig{}
		err = toml.Unmarshal(configData, &config)
		if err != nil {
			log.Fatal(err)
		}

		if len(config.Profiles) == 0 {
			fmt.Printf("no profiles found at %s\n", configPath)
			os.Exit(0)
		}

		tableData := [][]string{}
		for profileName, profile := range config.Profiles {
			// Only display the email if we're using API tokens otherwise the value is
			// not used and pretty superfluous.
			var emailString string
			if profile.AuthType == "api_key" {
				emailString = profile.Email
			}

			tableData = append(tableData, []string{
				profileName,
				profile.AuthType,
				emailString,
			})
		}

		table := tablewriter.NewWriter(os.Stdout)
		table.SetHeader([]string{"Profile name", "Authentication type", "Email"})
		table.SetAutoWrapText(false)
		table.SetAutoFormatHeaders(true)
		table.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
		table.SetAlignment(tablewriter.ALIGN_LEFT)
		table.SetCenterSeparator("")
		table.SetColumnSeparator("")
		table.SetRowSeparator("")
		table.SetHeaderLine(false)
		table.SetBorder(false)
		table.SetTablePadding("\t")
		table.SetNoWhiteSpace(true)
		table.AppendBulk(tableData)
		table.Render()
	},
}
