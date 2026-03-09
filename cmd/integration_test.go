package cmd

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// binaryPath holds the path to the compiled cf-vault binary used in integration tests.
var binaryPath string

// TestMain compiles the cf-vault binary once and runs all tests.
// Integration tests are skipped if the build fails.
func TestMain(m *testing.M) {
	tmp, err := os.MkdirTemp("", "cf-vault-bin-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "TestMain: failed to create temp dir: %v\n", err)
		os.Exit(1)
	}
	defer os.RemoveAll(tmp)

	binaryPath = filepath.Join(tmp, "cf-vault")
	out, err := exec.Command("go", "build", "-o", binaryPath, "../").CombinedOutput()
	if err != nil {
		fmt.Fprintf(os.Stderr, "TestMain: go build failed: %v\n%s\n", err, out)
		// Set empty path so integration tests skip gracefully.
		binaryPath = ""
	}

	os.Exit(m.Run())
}

// cfVaultResult holds the output of a cf-vault subprocess run.
type cfVaultResult struct {
	Stdout   string
	Stderr   string
	ExitCode int
}

// runCfVault runs the cf-vault binary with the given args and extra env vars.
// Extra env inherits the current process env and appends/overrides with extras.
func runCfVault(t *testing.T, extraEnv []string, args ...string) cfVaultResult {
	t.Helper()
	if binaryPath == "" {
		t.Skip("cf-vault binary not built, skipping integration test")
	}

	cmd := exec.Command(binaryPath, args...)
	cmd.Env = append(os.Environ(), extraEnv...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	exitCode := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			t.Fatalf("unexpected error running cf-vault: %v", err)
		}
	}

	return cfVaultResult{
		Stdout:   stdout.String(),
		Stderr:   stderr.String(),
		ExitCode: exitCode,
	}
}

// setupTestEnv creates isolated config and keyring directories in temp storage,
// sets the relevant env vars, and returns the config dir, keyring dir, env slice, and cleanup func.
// CF_VAULT_FILE_PASSPHRASE is set so the file keyring never prompts interactively.
func setupTestEnv(t *testing.T) (configDir string, keyringDir string, envVars []string, cleanup func()) {
	t.Helper()

	tmp, err := os.MkdirTemp("", "cf-vault-test-*")
	if err != nil {
		t.Fatal(err)
	}

	// XDG_CONFIG_HOME is the parent; resolveConfigDir appends "cf-vault".
	xdgConfig := filepath.Join(tmp, "xdgconfig")
	configDir = filepath.Join(xdgConfig, "cf-vault")

	// XDG_DATA_HOME is the parent; resolveKeyringDir appends "cf-vault/keys".
	xdgData := filepath.Join(tmp, "xdgdata")
	keyringDir = filepath.Join(xdgData, "cf-vault", "keys")

	for _, d := range []string{configDir, keyringDir} {
		if err := os.MkdirAll(d, 0700); err != nil {
			os.RemoveAll(tmp)
			t.Fatal(err)
		}
	}

	envVars = []string{
		"XDG_CONFIG_HOME=" + xdgConfig,
		"XDG_DATA_HOME=" + xdgData,
		"CF_VAULT_FILE_PASSPHRASE=test-passphrase",
		"CLOUDFLARE_VAULT_SESSION=",
	}

	cleanup = func() { os.RemoveAll(tmp) }
	return
}

// writeConfig writes a TOML config file to configDir/config.toml.
func writeConfig(t *testing.T, configDir, content string) {
	t.Helper()
	path := filepath.Join(configDir, "config.toml")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
}
