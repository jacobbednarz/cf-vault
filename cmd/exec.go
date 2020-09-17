package cmd

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"

	"os/exec"

	"github.com/99designs/keyring"
	"github.com/mitchellh/go-homedir"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"gopkg.in/ini.v1"
)

var execCmd = &cobra.Command{
	Use:   "exec [profile]",
	Short: "Execute a command with Cloudflare credentials populated",
	Long:  "",
	Example: `
  Execute a single command with credentials populated

    $ cf-vault exec example-profile -- env | grep -i cloudflare
    CLOUDFLARE_VAULT_SESSION=example-profile
    CLOUDFLARE_EMAIL=jacob@example.com
    CLOUDFLARE_API_KEY=s3cr3t

  Spawn a new shell with credentials populated

    $ cf-vault exec example-profile --
    $ env | grep -i cloudflare
    CLOUDFLARE_VAULT_SESSION=example-profile
    CLOUDFLARE_EMAIL=jacob@example.com
    CLOUDFLARE_API_KEY=s3cr3t
`,
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) < 1 {
			return errors.New("requires a profile argument")
		}
		return nil
	},
	PreRun: func(cmd *cobra.Command, args []string) {
		if verbose {
			log.SetLevel(log.DebugLevel)
		}
	},
	Run: func(cmd *cobra.Command, args []string) {
		profileName := args[0]
		// Remove the extra executable name at the beginning of the slice.
		copy(args[0:], args[0+1:])
		args[len(args)-1] = ""
		args = args[:len(args)-1]

		log.Debug("using profile: ", profileName)

		home, err := homedir.Dir()
		if err != nil {
			log.Fatal("unable to find home directory: ", err)
		}
		cfg, err := ini.Load(home + defaultFullConfigPath)
		profileSection, err := cfg.GetSection("profile " + profileName)
		if err != nil {
			log.Fatal("unable to create profile section: ", err)
		}

		if profileSection.Key("email").String() == "" {
			log.Fatalf("no profile matching %q found in the configuration file at %s", profileName, defaultFullConfigPath)
		}

		// Don't allow nesting of cf-vault sessions, it gets messy.
		if os.Getenv("CLOUDFLARE_VAULT_SESSION") != "" {
			log.Fatal("cf-vault sessions shouldn't be nested, unset CLOUDFLARE_VAULT_SESSION to continue or open a new shell session")
		}

		ring, err := keyring.Open(keyringDefaults)
		if err != nil {
			log.Fatalf("failed to open keyring backend: %s", strings.ToLower(err.Error()))
		}

		keychain, err := ring.Get(fmt.Sprintf("%s-%s", profileName, profileSection.Key("auth_type").String()))
		if err != nil {
			log.Fatalf("failed to get item from keyring: %s", strings.ToLower(err.Error()))
		}

		cloudflareCreds := []string{
			fmt.Sprintf("CLOUDFLARE_VAULT_SESSION=%s", profileName),
			fmt.Sprintf("CLOUDFLARE_EMAIL=%s", profileSection.Key("email").String()),
			fmt.Sprintf("CLOUDFLARE_%s=%s", strings.ToUpper(profileSection.Key("auth_type").String()), string(keychain.Data)),
		}

		// Should a command not be provided, drop into a fresh shell with the
		// credentials populated alongside the existing env.
		if len(args) == 0 {
			log.Debug("launching new shell with credentials populated")
			envVars := append(syscall.Environ(), cloudflareCreds...)
			syscall.Exec(os.Getenv("SHELL"), []string{os.Getenv("SHELL")}, envVars)
		}

		executable := args[0]
		pathtoExec, err := exec.LookPath(executable)
		if err != nil {
			log.Fatalf("couldn't find the executable '%s': %w", pathtoExec, err)
		}

		log.Debugf("found executable %s", pathtoExec)
		log.Debugf("executing command: %s", strings.Join(args, " "))

		syscall.Exec(pathtoExec, args, cloudflareCreds)
	},
}
