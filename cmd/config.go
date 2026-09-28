package cmd

import (
	"fmt"
	"os"
	"time"

	"github.com/pelletier/go-toml"
)

type tomlConfig struct {
	Profiles map[string]profile `toml:"profiles"`
}

type profile struct {
	Email           string   `toml:"email"`
	AuthType        string   `toml:"auth_type"`
	SessionDuration string   `toml:"session_duration,omitempty"`
	SecretBackend   string   `toml:"secret_backend,omitempty"`
	Policies        []policy `toml:"policies,omitempty"`
}

// validate reports mistakes in a profile's configuration, so they surface
// before its secret is unlocked or the Cloudflare API is called.
func (p profile) validate() error {
	if p.SessionDuration == "" {
		return nil
	}
	if _, err := parseSessionDuration(p.SessionDuration); err != nil {
		return fmt.Errorf(errFmtInvalidSessionDuration, err)
	}
	if len(p.Policies) == 0 {
		return errNoPoliciesForSessionDuration
	}
	_, err := p.tokenPolicies()
	return err
}

// minSessionDuration is the shortest short lived token lifetime accepted. A
// token that expires within moments of being created can lapse before the
// command gets to use it, from clock drift between this machine and
// Cloudflare or from the time taken to start the command.
const minSessionDuration = 10 * time.Second

// parseSessionDuration parses the lifetime of a short lived token, which must
// be at least minSessionDuration.
func parseSessionDuration(s string) (time.Duration, error) {
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, err
	}
	if d < minSessionDuration {
		return 0, fmt.Errorf(errFmtSessionDurationTooShort, s, minSessionDuration)
	}
	return d, nil
}

type policy struct {
	Effect           string                 `toml:"effect"`
	ID               string                 `toml:"id,omitempty"`
	PermissionGroups []permissionGroup      `toml:"permission_groups"`
	Resources        map[string]interface{} `toml:"resources"`
}

type permissionGroup struct {
	ID   string `toml:"id"`
	Name string `toml:"name,omitempty"`
}

// loadConfig reads and decodes the config file at path. A missing file is
// reported as an error wrapping fs.ErrNotExist.
func loadConfig(path string) (tomlConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return tomlConfig{}, err
	}

	var config tomlConfig
	if err := toml.Unmarshal(data, &config); err != nil {
		return tomlConfig{}, fmt.Errorf(errFmtParseConfigFile, path, err)
	}
	return config, nil
}

// saveConfig encodes config to the file at path, replacing its contents.
func saveConfig(path string, config tomlConfig) error {
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0700)
	if err != nil {
		return fmt.Errorf(errFmtOpenConfigFile, path, err)
	}
	defer file.Close()
	return toml.NewEncoder(file).Encode(config)
}
