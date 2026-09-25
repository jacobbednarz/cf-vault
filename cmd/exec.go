package cmd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"os/exec"

	"github.com/99designs/keyring"
	"github.com/cloudflare/cloudflare-go/v6"
	"github.com/cloudflare/cloudflare-go/v6/shared"
	"github.com/cloudflare/cloudflare-go/v6/user"
	"github.com/pelletier/go-toml"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

// credentialEnvVars are every variable `exec` may populate. Any of them already
// being set in the calling shell is a footgun: arguments like
// `-- echo $CLOUDFLARE_API_TOKEN` are expanded by that shell before cf-vault
// runs, so they silently carry the stale value instead of the profile's.
var credentialEnvVars = []string{
	envCloudflareEmail,
	envCFEmail,
	envPrefixCloudflare + strings.ToUpper(authTypeAPIKey),
	envPrefixCF + strings.ToUpper(authTypeAPIKey),
	envCloudflareAPIToken,
	envCFAPIToken,
	envCloudflareSessionExpiry,
}

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

  Reference the credentials in the command's arguments. The command must be
  wrapped in a shell with single quotes, otherwise your current shell expands
  the variables before cf-vault has populated them.

    $ cf-vault exec example-profile -- sh -c 'curl -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" https://api.cloudflare.com/client/v4/user/tokens/verify'

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
			return errProfileArgRequired
		}
		return nil
	},
	PreRun: func(cmd *cobra.Command, args []string) {
		if verbose {
			log.SetLevel(log.DebugLevel)
			keyring.Debug = true
		}
	},
	Run: func(cmd *cobra.Command, args []string) {
		env := environ(os.Environ())

		profileName := args[0]
		if err := validateProfileName(profileName); err != nil {
			log.Fatal(err)
		}
		// Remove the extra executable name at the beginning of the slice.
		copy(args[0:], args[0+1:])
		args[len(args)-1] = ""
		args = args[:len(args)-1]

		// Don't allow nesting of cf-vault sessions, it gets messy.
		if os.Getenv(envVaultSession) != "" {
			log.Fatal(errNestedSession)
		}

		var preexisting []string
		for _, name := range credentialEnvVars {
			if _, ok := os.LookupEnv(name); ok {
				preexisting = append(preexisting, name)
			}
		}
		if len(preexisting) > 0 {
			log.Warnf(msgFmtPreexistingCredentials, strings.Join(preexisting, ", "))
		}

		log.Debug("using profile: ", profileName)

		configDir, err := resolveConfigDir()
		if err != nil {
			log.Fatal(err)
		}
		configPath := filepath.Join(configDir, configFileName)

		configData, err := os.ReadFile(configPath)
		if err != nil {
			log.Fatal(err)
		}

		config := tomlConfig{}
		err = toml.Unmarshal(configData, &config)
		if err != nil {
			log.Fatal(err)
		}

		if _, ok := config.Profiles[profileName]; !ok {
			log.Fatalf(errFmtProfileNotFound, profileName, configPath)
		}

		profile := config.Profiles[profileName]

		var secret []byte
		switch profile.SecretBackend {
		case secretBackendAgeSE, secretBackendAgeYubikey:
			plaintext, err := decryptWithAge(ageIdentityPath(configDir, profile.SecretBackend), ageSecretPath(configDir, profileName))
			if err != nil {
				log.Fatalf(errFmtDecryptAgeBackend, profile.SecretBackend, err)
			}
			secret = plaintext
		case "":
			ring, err := openKeyring()
			if err != nil {
				log.Fatalf(errFmtOpenKeyring, strings.ToLower(err.Error()))
			}

			keychain, err := ring.Get(fmt.Sprintf("%s-%s", profileName, profile.AuthType))
			if err != nil {
				log.Fatalf(errFmtGetKeyringItem, strings.ToLower(err.Error()))
			}
			secret = keychain.Data
		default:
			log.Fatalf(errFmtUnknownSecretBackend, profileName, profile.SecretBackend, secretBackendAgeSE, secretBackendAgeYubikey)
		}

		env.Set(envVaultSession, profileName)

		// Not using short lived tokens so set the static API token or API key.
		if profile.SessionDuration == "" {
			if profile.AuthType == authTypeAPIKey {
				env.Set(envCloudflareEmail, profile.Email)
				env.Set(envCFEmail, profile.Email)
			}
			env.Set(envPrefixCloudflare+strings.ToUpper(profile.AuthType), string(secret))
			env.Set(envPrefixCF+strings.ToUpper(profile.AuthType), string(secret))
		} else {
			cfClient := newClient(string(secret), profile.AuthType, profile.Email)

			tokenPolicies := []shared.TokenPolicyParam{}
			for _, p := range profile.Policies {
				var groups []shared.TokenPolicyPermissionGroupParam
				for _, g := range p.PermissionGroups {
					groups = append(groups, shared.TokenPolicyPermissionGroupParam{
						ID: cloudflare.F(g.ID),
					})
				}
				resources := shared.TokenPolicyResourcesIAMResourcesTypeObjectStringParam{}
				for k, v := range p.Resources {
					if s, ok := v.(string); ok {
						resources[k] = s
					} else {
						resources[k] = fmt.Sprintf("%v", v)
					}
				}
				tokenPolicies = append(tokenPolicies, shared.TokenPolicyParam{
					Effect:           cloudflare.F(shared.TokenPolicyEffect(p.Effect)),
					PermissionGroups: cloudflare.F(groups),
					Resources:        cloudflare.F[shared.TokenPolicyResourcesUnionParam](resources),
				})
			}

			parsedSessionDuration, err := time.ParseDuration(profile.SessionDuration)
			if err != nil {
				log.Fatal(err)
			}
			now, _ := time.Parse(time.RFC3339, time.Now().UTC().Format(time.RFC3339))
			tokenExpiry := now.Add(time.Second * time.Duration(parsedSessionDuration.Seconds()))

			shortLivedToken, err := cfClient.User.Tokens.New(context.Background(), user.TokenNewParams{
				Name:      cloudflare.F(fmt.Sprintf("%s-%d", projectName, tokenExpiry.Unix())),
				NotBefore: cloudflare.F(now),
				ExpiresOn: cloudflare.F(tokenExpiry),
				Policies:  cloudflare.F(tokenPolicies),
			})
			if err != nil {
				log.Fatalf(errFmtCreateAPIToken, err)
			}

			if shortLivedToken.Value != "" {
				env.Set(envCloudflareAPIToken, shortLivedToken.Value)
				env.Set(envCFAPIToken, shortLivedToken.Value)
			}

			env.Set(envCloudflareSessionExpiry, strconv.Itoa(int(tokenExpiry.Unix())))
		}

		// Should a command not be provided, drop into a fresh shell with the
		// credentials populated alongside the existing env.
		if len(args) == 0 {
			log.Debug("launching new shell with credentials populated")
			syscall.Exec(os.Getenv(envShell), []string{os.Getenv(envShell)}, env)
		}

		executable := args[0]
		pathtoExec, err := exec.LookPath(executable)
		if err != nil {
			log.Fatalf(errFmtExecutableNotFound, pathtoExec, err.Error())
		}

		log.Debugf("found executable %s", pathtoExec)
		log.Debugf("executing command: %s", strings.Join(args, " "))

		syscall.Exec(pathtoExec, args, env)
	},
}
