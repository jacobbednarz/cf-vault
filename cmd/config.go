package cmd

import (
	"fmt"
	"os"
	"path/filepath"
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

// saveConfig replaces the config file at path with config, readable only by
// its owner. The new contents are written to a temporary file that is renamed
// over the old one, so a failed or interrupted write leaves the previous
// config intact instead of a truncated file.
func saveConfig(path string, config tomlConfig) error {
	// Rename replaces a symlink rather than writing through it, so resolve it
	// first to keep a linked config, such as one kept in a dotfiles repo.
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		path = resolved
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}

	// CreateTemp creates the file with mode 0600.
	tmp, err := os.CreateTemp(dir, "."+configFileName+".*")
	if err != nil {
		return err
	}
	// Cleans up after a failure; after the rename there is nothing to remove.
	defer os.Remove(tmp.Name())

	if err := toml.NewEncoder(tmp).Encode(config); err != nil {
		tmp.Close()
		return fmt.Errorf(errFmtEncodeConfigFile, err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
