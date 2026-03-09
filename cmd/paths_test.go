package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mitchellh/go-homedir"
)

func TestResolveConfigDir_Legacy(t *testing.T) {
	orig := os.Getenv("XDG_CONFIG_HOME")
	os.Unsetenv("XDG_CONFIG_HOME")
	defer os.Setenv("XDG_CONFIG_HOME", orig)
	dir, err := resolveConfigDir()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(dir, "/.cf-vault") {
		t.Errorf("expected legacy path ending in /.cf-vault, got %s", dir)
	}
}

func TestResolveConfigDir_XDG(t *testing.T) {
	os.Setenv("XDG_CONFIG_HOME", "/tmp/xdg-config")
	defer os.Unsetenv("XDG_CONFIG_HOME")
	dir, err := resolveConfigDir()
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join("/tmp/xdg-config", "cf-vault")
	if dir != want {
		t.Errorf("expected %s, got %s", want, dir)
	}
}

func TestResolveConfigDir_XDG_WarnIfLegacyExists(t *testing.T) {
	// Create a temp dir to act as HOME, with a legacy .cf-vault subdir inside it.
	tmpHome, err := os.MkdirTemp("", "cf-vault-home-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpHome)

	legacyDir := filepath.Join(tmpHome, ".cf-vault")
	if err := os.Mkdir(legacyDir, 0700); err != nil {
		t.Fatal(err)
	}

	// Override HOME so go-homedir resolves to our temp dir.
	origHome := os.Getenv("HOME")
	os.Setenv("HOME", tmpHome)
	defer os.Setenv("HOME", origHome)

	// Also clear the homedir cache so it picks up the new HOME.
	homedir.Reset()
	defer homedir.Reset()

	os.Setenv("XDG_CONFIG_HOME", "/tmp/xdg-config")
	defer os.Unsetenv("XDG_CONFIG_HOME")

	// Capture stderr.
	oldStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	_, err = resolveConfigDir()

	w.Close()
	os.Stderr = oldStderr

	var buf bytes.Buffer
	buf.ReadFrom(r)
	output := buf.String()

	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output, "Warning:") {
		t.Errorf("expected warning on stderr, got: %q", output)
	}
	if !strings.Contains(output, legacyDir) {
		t.Errorf("expected warning to mention legacy dir %s, got: %q", legacyDir, output)
	}
}

func TestResolveKeyringDir_Legacy(t *testing.T) {
	orig := os.Getenv("XDG_DATA_HOME")
	os.Unsetenv("XDG_DATA_HOME")
	defer os.Setenv("XDG_DATA_HOME", orig)
	dir, err := resolveKeyringDir()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(dir, "/.cf-vault/keys") {
		t.Errorf("expected legacy path ending in /.cf-vault/keys, got %s", dir)
	}
}

func TestResolveKeyringDir_XDG(t *testing.T) {
	os.Setenv("XDG_DATA_HOME", "/tmp/xdg-data")
	defer os.Unsetenv("XDG_DATA_HOME")
	dir, err := resolveKeyringDir()
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join("/tmp/xdg-data", "cf-vault", "keys")
	if dir != want {
		t.Errorf("expected %s, got %s", want, dir)
	}
}
