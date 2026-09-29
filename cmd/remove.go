package cmd

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var removeCmd = &cobra.Command{
	Use:     "remove [profile]",
	Aliases: []string{"rm"},
	Short:   "Remove a profile and its stored credential",
	Long:    "",
	Example: `
  Remove a profile (you will be asked to confirm)

    $ cf-vault remove example-profile

  Remove a profile without confirming, such as from a script

    $ cf-vault remove example-profile --force
`,
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) < 1 {
			return errProfileArgRequired
		}
		return cobra.ExactArgs(1)(cmd, args)
	},
	RunE: runRemove,
}

func runRemove(cmd *cobra.Command, args []string) error {
	profileName := args[0]
	if err := validateProfileName(profileName); err != nil {
		return err
	}
	force, _ := cmd.Flags().GetBool(flagForce)

	configDir, err := resolveConfigDir()
	if err != nil {
		return err
	}
	configPath := filepath.Join(configDir, configFileName)

	config, err := loadConfig(configPath)
	if err != nil {
		return err
	}
	p, ok := config.Profiles[profileName]
	if !ok {
		return fmt.Errorf(errFmtProfileNotFound, profileName, configPath)
	}

	if !force {
		// Without a terminal there is nobody to answer, and reading piped
		// stdin as the answer would act on input meant for something else.
		if !term.IsTerminal(int(os.Stdin.Fd())) {
			return errRemoveNeedsConfirmation
		}
		if !confirmRemoval(profileName, os.Stdin, os.Stdout) {
			return errRemoveNotConfirmed
		}
	}

	// The credential goes first. Should that fail, the profile still points
	// at it and `remove` can be run again; removing the profile first would
	// leave the credential stranded where cf-vault can no longer find it.
	store, err := openSecretStore(configDir, profileName, p)
	if err != nil {
		return err
	}
	if err := store.Delete(); err != nil {
		return err
	}

	delete(config.Profiles, profileName)
	if err := saveConfig(configPath, config); err != nil {
		return err
	}

	fmt.Printf(msgFmtRemoved, profileName)
	return nil
}

// confirmRemoval asks whether to remove the named profile, reading the answer
// from in. Only an explicit yes confirms.
func confirmRemoval(profileName string, in io.Reader, out io.Writer) bool {
	fmt.Fprintf(out, promptFmtConfirmRemove, profileName)
	line, _ := bufio.NewReader(in).ReadString('\n')
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true
	}
	return false
}
