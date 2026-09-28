package cmd

import (
	"os"
	"path/filepath"
	"testing"
)

var savedConfig = tomlConfig{Profiles: map[string]profile{
	"work": {AuthType: authTypeAPIToken},
}}

func TestSaveConfig_OnlyOwnerCanRead(t *testing.T) {
	for name, existing := range map[string]bool{"new file": false, "replacing a 0700 file": true} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "cf-vault", configFileName)
			if existing {
				if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, nil, 0o700); err != nil {
					t.Fatal(err)
				}
			}

			if err := saveConfig(path, savedConfig); err != nil {
				t.Fatal(err)
			}

			info, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if mode := info.Mode().Perm(); mode != 0o600 {
				t.Errorf("config mode = %o, want 600", mode)
			}
			if got, err := loadConfig(path); err != nil || got.Profiles["work"].AuthType != authTypeAPIToken {
				t.Errorf("loadConfig after save = %+v, %v", got, err)
			}
		})
	}
}

// A write that fails part way must leave the previous config in place, not a
// truncated file that has lost every profile.
func TestSaveConfig_FailedWriteKeepsPreviousConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, configFileName)
	const previous = "[profiles.work]\nauth_type = \"api_token\"\n"
	if err := os.WriteFile(path, []byte(previous), 0o600); err != nil {
		t.Fatal(err)
	}

	unencodable := tomlConfig{Profiles: map[string]profile{
		"broken": {Policies: []policy{{Resources: map[string]interface{}{"x": make(chan int)}}}},
	}}
	if err := saveConfig(path, unencodable); err == nil {
		t.Fatal("expected encoding to fail")
	}

	if data, _ := os.ReadFile(path); string(data) != previous {
		t.Errorf("config after failed save = %q, want it untouched", data)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Errorf("expected only the config file to remain, got %v", entries)
	}
}

// Replacing the file by renaming over it must not swap a symlinked config,
// such as one managed from a dotfiles repository, for a regular file.
func TestSaveConfig_WritesThroughSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "dotfiles", configFileName)
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, configFileName)
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	if err := saveConfig(link, savedConfig); err != nil {
		t.Fatal(err)
	}

	if info, err := os.Lstat(link); err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("expected %s to remain a symlink, got %v, %v", link, info, err)
	}
	if got, err := loadConfig(target); err != nil || got.Profiles["work"].AuthType != authTypeAPIToken {
		t.Errorf("symlink target after save = %+v, %v", got, err)
	}
}
