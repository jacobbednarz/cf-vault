package cmd

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/99designs/keyring"
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

func TestIntegration_Version(t *testing.T) {
	result := runCfVault(t, nil, "version")

	if result.ExitCode != 0 {
		t.Fatalf("expected exit 0, got %d\nstderr: %s", result.ExitCode, result.Stderr)
	}

	if !strings.Contains(result.Stdout, "cf-vault") {
		t.Errorf("expected 'cf-vault' in output, got: %q", result.Stdout)
	}

	// Format: cf-vault <version> (goX.Y.Z,gc-amd64)
	if !strings.Contains(result.Stdout, "(") {
		t.Errorf("expected version format with parentheses, got: %q", result.Stdout)
	}
}

func TestIntegration_List_NoProfiles(t *testing.T) {
	configDir, _, envVars, cleanup := setupTestEnv(t)
	defer cleanup()

	// Write a config file with no profiles section.
	writeConfig(t, configDir, "")

	result := runCfVault(t, envVars, "list")

	if result.ExitCode != 0 {
		t.Fatalf("expected exit 0, got %d\nstderr: %s", result.ExitCode, result.Stderr)
	}
	if !strings.Contains(result.Stdout, "no profiles found") {
		t.Errorf("expected 'no profiles found' in output, got: %q", result.Stdout)
	}
}

func TestIntegration_List_APIKeyProfile(t *testing.T) {
	configDir, _, envVars, cleanup := setupTestEnv(t)
	defer cleanup()

	writeConfig(t, configDir, `
[profiles]
  [profiles.myprofile]
    email = "test@example.com"
    auth_type = "api_key"
`)

	result := runCfVault(t, envVars, "list")

	if result.ExitCode != 0 {
		t.Fatalf("expected exit 0, got %d\nstderr: %s", result.ExitCode, result.Stderr)
	}
	if !strings.Contains(result.Stdout, "myprofile") {
		t.Errorf("expected 'myprofile' in output, got: %q", result.Stdout)
	}
	if !strings.Contains(result.Stdout, "api_key") {
		t.Errorf("expected 'api_key' in output, got: %q", result.Stdout)
	}
	if !strings.Contains(result.Stdout, "test@example.com") {
		t.Errorf("expected email in output for api_key profile, got: %q", result.Stdout)
	}
}

func TestIntegration_List_APITokenProfile(t *testing.T) {
	configDir, _, envVars, cleanup := setupTestEnv(t)
	defer cleanup()

	writeConfig(t, configDir, `
[profiles]
  [profiles.tokenprofile]
    auth_type = "api_token"
    email = "token@example.com"
`)

	result := runCfVault(t, envVars, "list")

	if result.ExitCode != 0 {
		t.Fatalf("expected exit 0, got %d\nstderr: %s", result.ExitCode, result.Stderr)
	}
	if !strings.Contains(result.Stdout, "tokenprofile") {
		t.Errorf("expected 'tokenprofile' in output, got: %q", result.Stdout)
	}
	if !strings.Contains(result.Stdout, "api_token") {
		t.Errorf("expected 'api_token' in output, got: %q", result.Stdout)
	}
	// Email should NOT appear for api_token profiles.
	if strings.Contains(result.Stdout, "token@example.com") {
		t.Errorf("email should not appear for api_token profile, got: %q", result.Stdout)
	}
}

func TestIntegration_List_MultipleProfiles(t *testing.T) {
	configDir, _, envVars, cleanup := setupTestEnv(t)
	defer cleanup()

	writeConfig(t, configDir, `
[profiles]
  [profiles.profile-one]
    email = "one@example.com"
    auth_type = "api_key"
  [profiles.profile-two]
    auth_type = "api_token"
`)

	result := runCfVault(t, envVars, "list")

	if result.ExitCode != 0 {
		t.Fatalf("expected exit 0, got %d\nstderr: %s", result.ExitCode, result.Stderr)
	}
	if !strings.Contains(result.Stdout, "profile-one") {
		t.Errorf("expected 'profile-one' in output, got: %q", result.Stdout)
	}
	if !strings.Contains(result.Stdout, "profile-two") {
		t.Errorf("expected 'profile-two' in output, got: %q", result.Stdout)
	}
}

func TestIntegration_Exec_MissingProfileArg(t *testing.T) {
	result := runCfVault(t, nil, "exec")

	if result.ExitCode == 0 {
		t.Fatalf("expected non-zero exit for missing profile arg, got 0\nstdout: %s", result.Stdout)
	}

	combined := result.Stdout + result.Stderr
	if !strings.Contains(combined, "requires a profile argument") {
		t.Errorf("expected 'requires a profile argument' in output, got stdout=%q stderr=%q",
			result.Stdout, result.Stderr)
	}
}

func TestIntegration_Exec_ProfileNotFound(t *testing.T) {
	configDir, _, envVars, cleanup := setupTestEnv(t)
	defer cleanup()

	writeConfig(t, configDir, `
[profiles]
  [profiles.someprofile]
    auth_type = "api_token"
`)

	result := runCfVault(t, envVars, "exec", "nonexistent-profile", "--", "env")

	if result.ExitCode == 0 {
		t.Fatalf("expected non-zero exit for unknown profile, got 0")
	}
	if !strings.Contains(result.Stderr, "nonexistent-profile") {
		t.Errorf("expected profile name in error output, got stderr=%q", result.Stderr)
	}
}

func TestIntegration_Exec_NestedSessionRejected(t *testing.T) {
	configDir, _, envVars, cleanup := setupTestEnv(t)
	defer cleanup()

	writeConfig(t, configDir, `
[profiles]
  [profiles.myprofile]
    auth_type = "api_token"
`)

	// Override the empty CLOUDFLARE_VAULT_SESSION with a real value to simulate nesting.
	envVars = append(envVars, "CLOUDFLARE_VAULT_SESSION=existing-session")

	result := runCfVault(t, envVars, "exec", "myprofile", "--", "env")

	if result.ExitCode == 0 {
		t.Fatalf("expected non-zero exit when session already set, got 0")
	}
	if !strings.Contains(result.Stderr, "shouldn't be nested") {
		t.Errorf("expected nesting error message in stderr, got: %q", result.Stderr)
	}
}

// writeKeyringItem stores a credential in the file keyring at keyringDir using the
// same passphrase set in CF_VAULT_FILE_PASSPHRASE ("test-passphrase").
func writeKeyringItem(t *testing.T, keyringDir, key string, data []byte) {
	t.Helper()

	cfg := keyringDefaults
	cfg.AllowedBackends = []keyring.BackendType{keyring.FileBackend}
	cfg.FileDir = keyringDir + "/"
	cfg.FilePasswordFunc = func(_ string) (string, error) {
		return "test-passphrase", nil
	}

	ring, err := keyring.Open(cfg)
	if err != nil {
		t.Fatalf("writeKeyringItem: failed to open keyring: %v", err)
	}
	if err := ring.Set(keyring.Item{Key: key, Data: data}); err != nil {
		t.Fatalf("writeKeyringItem: failed to set item %q: %v", key, err)
	}
}

func TestIntegration_Exec_APIKey(t *testing.T) {
	configDir, keyringDir, envVars, cleanup := setupTestEnv(t)
	defer cleanup()

	// Remove the empty CLOUDFLARE_VAULT_SESSION so exec doesn't see a stale session.
	filtered := make([]string, 0, len(envVars))
	for _, e := range envVars {
		if !strings.HasPrefix(e, "CLOUDFLARE_VAULT_SESSION=") {
			filtered = append(filtered, e)
		}
	}
	envVars = filtered

	writeConfig(t, configDir, `
[profiles]
  [profiles.testprofile]
    email = "user@example.com"
    auth_type = "api_key"
`)

	// Pre-populate the keyring. Key = "{profileName}-{authType}"
	writeKeyringItem(t, keyringDir, "testprofile-api_key", []byte("a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f"))

	result := runCfVault(t, envVars, "exec", "testprofile", "--", "env")

	if result.ExitCode != 0 {
		t.Fatalf("expected exit 0, got %d\nstderr: %s", result.ExitCode, result.Stderr)
	}

	if !strings.Contains(result.Stdout, "CLOUDFLARE_EMAIL=user@example.com") {
		t.Errorf("expected CLOUDFLARE_EMAIL in output, got:\n%s", result.Stdout)
	}
	if !strings.Contains(result.Stdout, "CF_EMAIL=user@example.com") {
		t.Errorf("expected CF_EMAIL in output, got:\n%s", result.Stdout)
	}
	if !strings.Contains(result.Stdout, "CLOUDFLARE_API_KEY=") {
		t.Errorf("expected CLOUDFLARE_API_KEY in output, got:\n%s", result.Stdout)
	}
	if !strings.Contains(result.Stdout, "CF_API_KEY=") {
		t.Errorf("expected CF_API_KEY in output, got:\n%s", result.Stdout)
	}
	if !strings.Contains(result.Stdout, "CLOUDFLARE_VAULT_SESSION=testprofile") {
		t.Errorf("expected CLOUDFLARE_VAULT_SESSION=testprofile in output, got:\n%s", result.Stdout)
	}
}

func TestIntegration_Exec_APIToken(t *testing.T) {
	configDir, keyringDir, envVars, cleanup := setupTestEnv(t)
	defer cleanup()

	filtered := make([]string, 0, len(envVars))
	for _, e := range envVars {
		if !strings.HasPrefix(e, "CLOUDFLARE_VAULT_SESSION=") {
			filtered = append(filtered, e)
		}
	}
	envVars = filtered

	writeConfig(t, configDir, `
[profiles]
  [profiles.tokenprofile]
    auth_type = "api_token"
`)

	// A valid 40-char API token value.
	writeKeyringItem(t, keyringDir, "tokenprofile-api_token", []byte("abcdefghijklmnopqrstuvwxyzABCDEF12345678"))

	result := runCfVault(t, envVars, "exec", "tokenprofile", "--", "env")

	if result.ExitCode != 0 {
		t.Fatalf("expected exit 0, got %d\nstderr: %s", result.ExitCode, result.Stderr)
	}

	if !strings.Contains(result.Stdout, "CLOUDFLARE_API_TOKEN=") {
		t.Errorf("expected CLOUDFLARE_API_TOKEN in output, got:\n%s", result.Stdout)
	}
	if !strings.Contains(result.Stdout, "CF_API_TOKEN=") {
		t.Errorf("expected CF_API_TOKEN in output, got:\n%s", result.Stdout)
	}
	// Email should NOT be set for api_token profiles.
	if strings.Contains(result.Stdout, "CLOUDFLARE_EMAIL=") {
		t.Errorf("CLOUDFLARE_EMAIL should not be set for api_token profile, got:\n%s", result.Stdout)
	}
	if !strings.Contains(result.Stdout, "CLOUDFLARE_VAULT_SESSION=tokenprofile") {
		t.Errorf("expected CLOUDFLARE_VAULT_SESSION=tokenprofile in output, got:\n%s", result.Stdout)
	}
}
