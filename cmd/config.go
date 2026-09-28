package cmd

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/pelletier/go-toml"
)

type tomlConfig struct {
	Profiles map[string]profile `toml:"profiles"`
}

type profile struct {
	Email    string `toml:"email"`
	AuthType string `toml:"auth_type"`
	// OwnerAccountID is set when the profile's API token is owned by that
	// account rather than a user. Short lived tokens are then created in, and
	// can only reach, that account.
	OwnerAccountID  string   `toml:"owner_account_id,omitempty"`
	SessionDuration string   `toml:"session_duration,omitempty"`
	SecretBackend   string   `toml:"secret_backend,omitempty"`
	Policies        []policy `toml:"policies,omitempty"`
}

// validate reports mistakes in a profile's configuration, so they surface
// before its secret is unlocked or the Cloudflare API is called.
func (p profile) validate() error {
	if p.AuthType != authTypeAPIKey && p.AuthType != authTypeAPIToken {
		return fmt.Errorf(errFmtUnknownAuthType, p.AuthType, authTypeAPIKey, authTypeAPIToken)
	}
	if p.OwnerAccountID != "" {
		if p.AuthType == authTypeAPIKey {
			return errOwnerAccountIDForAPIKey
		}
		// The ID becomes part of the API path tokens are created at.
		if err := validateResourceIDs("owner account", []string{p.OwnerAccountID}); err != nil {
			return err
		}
	}
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
	PermissionGroups []permissionGroup      `toml:"permission_groups"`
	Resources        map[string]interface{} `toml:"resources"`
}

type permissionGroup struct {
	ID   string `toml:"id"`
	Name string `toml:"name,omitempty"`
}

// loadConfig reads and decodes the config file at path. A file that doesn't
// exist yet is an empty config: nothing has been added.
func loadConfig(path string) (tomlConfig, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return tomlConfig{}, nil
	}
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
	// Rename replaces a symlink rather than writing through it, so find the
	// file it leads to first to keep a linked config, such as one kept in a
	// dotfiles repo.
	path, err := symlinkTarget(path)
	if err != nil {
		return err
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

// maxSymlinkHops bounds symlinkTarget, matching the limit Linux applies
// before giving up on a loop of links.
const maxSymlinkHops = 40

// symlinkTarget follows path through any symlinks to the file they lead to,
// which, unlike with filepath.EvalSymlinks, need not exist yet.
func symlinkTarget(path string) (string, error) {
	for range maxSymlinkHops {
		info, err := os.Lstat(path)
		if errors.Is(err, fs.ErrNotExist) || (err == nil && info.Mode()&os.ModeSymlink == 0) {
			return path, nil
		}
		if err != nil {
			return "", err
		}
		target, err := os.Readlink(path)
		if err != nil {
			return "", err
		}
		if !filepath.IsAbs(target) {
			// A relative link is relative to the directory it really lives
			// in, which may itself be reached through a symlink.
			dir, err := filepath.EvalSymlinks(filepath.Dir(path))
			if err != nil {
				return "", err
			}
			target = filepath.Join(dir, target)
		}
		path = target
	}
	return "", fmt.Errorf(errFmtConfigSymlinkLoop, path)
}
