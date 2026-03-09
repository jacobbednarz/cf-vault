package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/99designs/keyring"
	"github.com/mitchellh/go-homedir"
)

// resolveConfigDir returns the directory used for cf-vault's config file.
// If XDG_CONFIG_HOME is set it returns $XDG_CONFIG_HOME/cf-vault; otherwise
// it falls back to the legacy ~/.cf-vault path.
// When XDG is active and the legacy directory still exists, a migration
// warning is printed to stderr.
func resolveConfigDir() (string, error) {
	home, err := homedir.Dir()
	if err != nil {
		return "", fmt.Errorf("unable to find home directory: %w", err)
	}

	legacyDir := filepath.Join(home, "."+projectName)

	xdgConfigHome := os.Getenv("XDG_CONFIG_HOME")
	if xdgConfigHome != "" {
		xdgDir := filepath.Join(xdgConfigHome, projectName)
		if _, statErr := os.Stat(legacyDir); statErr == nil {
			fmt.Fprintf(os.Stderr,
				"Warning: XDG directories are configured but legacy data exists at %s. "+
					"Consider migrating your config and keys to the new XDG-compliant locations.\n",
				legacyDir)
		}
		return xdgDir, nil
	}

	return legacyDir, nil
}

// resolveKeyringDir returns the directory used by the file-based keyring backend.
// If XDG_DATA_HOME is set it returns $XDG_DATA_HOME/cf-vault/keys; otherwise
// it falls back to the legacy ~/.cf-vault/keys path.
func resolveKeyringDir() (string, error) {
	home, err := homedir.Dir()
	if err != nil {
		return "", fmt.Errorf("unable to find home directory: %w", err)
	}

	xdgDataHome := os.Getenv("XDG_DATA_HOME")
	if xdgDataHome != "" {
		return filepath.Join(xdgDataHome, projectName, "keys"), nil
	}

	return filepath.Join(home, "."+projectName, "keys"), nil
}

// openKeyring opens the keyring backend with paths resolved via resolveKeyringDir.
func openKeyring() (keyring.Keyring, error) {
	keyringDir, err := resolveKeyringDir()
	if err != nil {
		return nil, err
	}

	cfg := keyringDefaults
	cfg.FileDir = keyringDir + "/"
	return keyring.Open(cfg)
}
