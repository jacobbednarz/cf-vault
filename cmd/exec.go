package cmd

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"os/exec"

	"github.com/99designs/keyring"
	"github.com/cloudflare/cloudflare-go"
	"github.com/mitchellh/go-homedir"
	"github.com/pelletier/go-toml"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
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
    CF_EMAIL=jacob@example.com
    CF_API_KEY=s3cr3t

  Spawn a new shell with credentials populated

    $ cf-vault exec example-profile --
    $ env | grep -i cloudflare
    CLOUDFLARE_VAULT_SESSION=example-profile
    CLOUDFLARE_EMAIL=jacob@example.com
    CLOUDFLARE_API_KEY=s3cr3t
    CF_EMAIL=jacob@example.com
    CF_API_KEY=s3cr3t
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
		env := environ(os.Environ())

		profileName := args[0]
		// Remove the extra executable name at the beginning of the slice.
		copy(args[0:], args[0+1:])
		args[len(args)-1] = ""
		args = args[:len(args)-1]

		// Don't allow nesting of cf-vault sessions, it gets messy.
		if os.Getenv("CLOUDFLARE_VAULT_SESSION") != "" {
			log.Fatal("cf-vault sessions shouldn't be nested, unset CLOUDFLARE_VAULT_SESSION to continue or open a new shell session")
		}

		log.Debug("using profile: ", profileName)

		home, err := homedir.Dir()
		if err != nil {
			log.Fatal("unable to find home directory: ", err)
		}

		configData, err := ioutil.ReadFile(home + defaultFullConfigPath)
		if err != nil {
			log.Fatal(err)
		}

		config := tomlConfig{}
		err = toml.Unmarshal(configData, &config)
		if err != nil {
			log.Fatal(err)
		}

		if _, ok := config.Profiles[profileName]; !ok {
			log.Fatalf("no profile matching %q found in the configuration file at %s", profileName, home+defaultFullConfigPath)
		}

		profile := config.Profiles[profileName]

		ring, err := keyring.Open(keyringDefaults)
		if err != nil {
			log.Fatalf("failed to open keyring backend: %s", strings.ToLower(err.Error()))
		}

		keychain, err := ring.Get(fmt.Sprintf("%s-%s", profileName, profile.AuthType))
		if err != nil {
			log.Fatalf("failed to get item from keyring: %s", strings.ToLower(err.Error()))
		}

		env.Set("CLOUDFLARE_VAULT_SESSION", profileName)

		// Not using short lived tokens so set the static API token or API key.
		if profile.SessionDuration == "" {
			if profile.AuthType == "api_key" {
				env.Set("CLOUDFLARE_EMAIL", profile.Email)
				env.Set("CF_EMAIL", profile.Email)
			}
			env.Set(fmt.Sprintf("CLOUDFLARE_%s", strings.ToUpper(profile.AuthType)), string(keychain.Data))
			env.Set(fmt.Sprintf("CF_%s", strings.ToUpper(profile.AuthType)), string(keychain.Data))
		} else {
			var api *cloudflare.API
			if profile.AuthType == "api_token" {
				api, err = cloudflare.NewWithAPIToken(string(keychain.Data))
				if err != nil {
					log.Fatal(err)
				}
			} else {
				api, err = cloudflare.New(string(keychain.Data), profile.Email)
				if err != nil {
					log.Fatal(err)
				}
			}

			policies := []cloudflare.APITokenPolicies{}

			for _, policy := range profile.Policies {
				permissionGroups := []cloudflare.APITokenPermissionGroups{}
				for _, group := range policy.PermissionGroups {
					permissionGroups = append(permissionGroups, cloudflare.APITokenPermissionGroups{
						ID:   group.ID,
						Name: group.Name,
					})
				}

				policies = append(policies, cloudflare.APITokenPolicies{
					Effect:           policy.Effect,
					Resources:        policy.Resources,
					PermissionGroups: permissionGroups,
				})
			}

			parsedSessionDuration, err := time.ParseDuration(profile.SessionDuration)
			if err != nil {
				log.Fatal(err)
			}
			now, _ := time.Parse(time.RFC3339, time.Now().UTC().Format(time.RFC3339))
			tokenExpiry := now.Add(time.Second * time.Duration(parsedSessionDuration.Seconds()))

			token := cloudflare.APIToken{
				Name:      fmt.Sprintf("%s-%d", projectName, tokenExpiry.Unix()),
				NotBefore: &now,
				ExpiresOn: &tokenExpiry,
				Policies:  policies,
			}

			shortLivedToken, err := api.CreateAPIToken(token)
			if err != nil {
				log.Fatalf("failed to create API token: %s", err)
			}

			if shortLivedToken.Value != "" {
				env.Set("CLOUDFLARE_API_TOKEN", shortLivedToken.Value)
				env.Set("CF_API_TOKEN", shortLivedToken.Value)
			}

			env.Set("CLOUDFLARE_SESSION_EXPIRY", strconv.Itoa(int(tokenExpiry.Unix())))
		}

		// Should a command not be provided, drop into a fresh shell with the
		// credentials populated alongside the existing env.
		if len(args) == 0 {
			log.Debug("launching new shell with credentials populated")
			syscall.Exec(os.Getenv("SHELL"), []string{os.Getenv("SHELL")}, env)
		}

		executable := args[0]
		pathtoExec, err := exec.LookPath(executable)
		if err != nil {
			log.Fatalf("couldn't find the executable '%s': %s", pathtoExec, err.Error())
		}

		log.Debugf("found executable %s", pathtoExec)
		log.Debugf("executing command: %s", strings.Join(args, " "))

		syscall.Exec(pathtoExec, args, env)
	},
}
