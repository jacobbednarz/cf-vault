package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/olekukonko/tablewriter"
	"github.com/spf13/cobra"
)

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List all available profiles",
	Long:  "",
	RunE:  runList,
}

func runList(cmd *cobra.Command, args []string) error {
	configDir, err := resolveConfigDir()
	if err != nil {
		return err
	}
	configPath := filepath.Join(configDir, configFileName)

	config, err := loadConfig(configPath)
	if err != nil {
		return err
	}

	if len(config.Profiles) == 0 {
		fmt.Printf(msgFmtNoProfilesFound, configPath)
		return nil
	}

	tableData := [][]string{}
	for profileName, profile := range config.Profiles {
		// Only display the email if we're using API tokens otherwise the value is
		// not used and pretty superfluous.
		var emailString string
		if profile.AuthType == authTypeAPIKey {
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
	return nil
}
