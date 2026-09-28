package cmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
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

	code := m.Run()
	os.RemoveAll(tmp)
	os.Exit(code)
}

// cfVaultResult holds the output of a cf-vault subprocess run.
type cfVaultResult struct {
	Stdout   string
	Stderr   string
	ExitCode int
}

// runCfVault runs the cf-vault binary with the given args and extra env vars.
// Extra env inherits the current process env and appends/overrides with extras.
// Credentials exported in the developer's shell or CI are stripped first so
// they can't leak into `exec` assertions or trigger its preexisting warning.
func runCfVault(t *testing.T, extraEnv []string, args ...string) cfVaultResult {
	t.Helper()
	return runCfVaultWithStdin(t, extraEnv, nil, args...)
}

// runCfVaultWithStdin is runCfVault with stdin connected to the given reader.
// A nil reader leaves stdin attached to the null device.
func runCfVaultWithStdin(t *testing.T, extraEnv []string, stdin io.Reader, args ...string) cfVaultResult {
	t.Helper()
	if binaryPath == "" {
		t.Skip("cf-vault binary not built, skipping integration test")
	}

	env := environ(os.Environ())
	for _, name := range credentialEnvVars {
		env.Unset(name)
	}
	env.Unset(envAuthValue)

	cmd := exec.Command(binaryPath, args...)
	cmd.Env = append(env, extraEnv...)
	cmd.Stdin = stdin

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
		"CF_VAULT_BACKEND=file",
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

	if err := openTestKeyring(t, keyringDir).Set(keyring.Item{Key: key, Data: data}); err != nil {
		t.Fatalf("writeKeyringItem: failed to set item %q: %v", key, err)
	}
}

// readKeyringItem returns the data stored under key in the test file keyring,
// and whether it exists at all.
func readKeyringItem(t *testing.T, keyringDir, key string) ([]byte, bool) {
	t.Helper()

	item, err := openTestKeyring(t, keyringDir).Get(key)
	if errors.Is(err, keyring.ErrKeyNotFound) {
		return nil, false
	}
	if err != nil {
		t.Fatalf("readKeyringItem: failed to get item %q: %v", key, err)
	}
	return item.Data, true
}

func openTestKeyring(t *testing.T, keyringDir string) keyring.Keyring {
	t.Helper()

	cfg := keyringDefaults
	cfg.AllowedBackends = []keyring.BackendType{keyring.FileBackend}
	cfg.FileDir = keyringDir + "/"
	cfg.FilePasswordFunc = func(_ string) (string, error) {
		return "test-passphrase", nil
	}

	ring, err := keyring.Open(cfg)
	if err != nil {
		t.Fatalf("openTestKeyring: failed to open keyring: %v", err)
	}
	return ring
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
	if !strings.Contains(result.Stdout, "CLOUDFLARE_API_KEY=a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f") {
		t.Errorf("expected CLOUDFLARE_API_KEY with correct value in output, got:\n%s", result.Stdout)
	}
	if !strings.Contains(result.Stdout, "CF_API_KEY=a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f") {
		t.Errorf("expected CF_API_KEY with correct value in output, got:\n%s", result.Stdout)
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

	if !strings.Contains(result.Stdout, "CLOUDFLARE_API_TOKEN=abcdefghijklmnopqrstuvwxyzABCDEF12345678") {
		t.Errorf("expected CLOUDFLARE_API_TOKEN with correct value in output, got:\n%s", result.Stdout)
	}
	if !strings.Contains(result.Stdout, "CF_API_TOKEN=abcdefghijklmnopqrstuvwxyzABCDEF12345678") {
		t.Errorf("expected CF_API_TOKEN with correct value in output, got:\n%s", result.Stdout)
	}
	// Email should NOT be set for api_token profiles.
	if strings.Contains(result.Stdout, "CLOUDFLARE_EMAIL=") {
		t.Errorf("CLOUDFLARE_EMAIL should not be set for api_token profile, got:\n%s", result.Stdout)
	}
	if !strings.Contains(result.Stdout, "CLOUDFLARE_VAULT_SESSION=tokenprofile") {
		t.Errorf("expected CLOUDFLARE_VAULT_SESSION=tokenprofile in output, got:\n%s", result.Stdout)
	}
}

func TestIntegration_Exec_WarnsOnPreexistingCredentials(t *testing.T) {
	configDir, keyringDir, envVars, cleanup := setupTestEnv(t)
	defer cleanup()

	filtered := make([]string, 0, len(envVars))
	for _, e := range envVars {
		if !strings.HasPrefix(e, "CLOUDFLARE_VAULT_SESSION=") {
			filtered = append(filtered, e)
		}
	}
	envVars = append(filtered, "CLOUDFLARE_API_TOKEN=stale", "CF_API_KEY=stale")

	writeConfig(t, configDir, `
[profiles]
  [profiles.tokenprofile]
    auth_type = "api_token"
`)
	writeKeyringItem(t, keyringDir, "tokenprofile-api_token", []byte("abcdefghijklmnopqrstuvwxyzABCDEF12345678"))

	result := runCfVault(t, envVars, "exec", "tokenprofile", "--", "env")

	if result.ExitCode != 0 {
		t.Fatalf("expected exit 0, got %d\nstderr: %s", result.ExitCode, result.Stderr)
	}
	if !strings.Contains(result.Stderr, "CLOUDFLARE_API_TOKEN") || !strings.Contains(result.Stderr, "CF_API_KEY") {
		t.Errorf("expected warning naming both preexisting variables, got: %q", result.Stderr)
	}
	// The profile's value must still win in the child's environment.
	if !strings.Contains(result.Stdout, "CLOUDFLARE_API_TOKEN=abcdefghijklmnopqrstuvwxyzABCDEF12345678") {
		t.Errorf("expected profile CLOUDFLARE_API_TOKEN to override stale value, got:\n%s", result.Stdout)
	}
	// Credentials the profile doesn't use must not reach the child either,
	// or it sees a stale API key alongside the profile's token.
	if strings.Contains(result.Stdout, "CF_API_KEY=") {
		t.Errorf("expected stale CF_API_KEY to be removed, got:\n%s", result.Stdout)
	}
}

func TestIntegration_Exec_NoWarningWithoutPreexistingCredentials(t *testing.T) {
	configDir, keyringDir, envVars, cleanup := setupTestEnv(t)
	defer cleanup()

	writeConfig(t, configDir, `
[profiles]
  [profiles.tokenprofile]
    auth_type = "api_token"
`)
	writeKeyringItem(t, keyringDir, "tokenprofile-api_token", []byte("abcdefghijklmnopqrstuvwxyzABCDEF12345678"))

	result := runCfVault(t, envVars, "exec", "tokenprofile", "--", "env")

	if result.ExitCode != 0 {
		t.Fatalf("expected exit 0, got %d\nstderr: %s", result.ExitCode, result.Stderr)
	}
	if strings.Contains(result.Stderr, "already set in the calling shell") {
		t.Errorf("expected no warning, got: %q", result.Stderr)
	}
}

// setupTokenProfile returns the env for an isolated test install holding a
// single long lived API token profile named "tokenprofile".
func setupTokenProfile(t *testing.T) []string {
	t.Helper()

	configDir, keyringDir, envVars, cleanup := setupTestEnv(t)
	t.Cleanup(cleanup)

	writeConfig(t, configDir, `
[profiles]
  [profiles.tokenprofile]
    auth_type = "api_token"
`)
	writeKeyringItem(t, keyringDir, "tokenprofile-api_token", []byte(testAPIToken))
	return envVars
}

func TestIntegration_Exec_NoCommandWithoutShell(t *testing.T) {
	for name, shell := range map[string]string{
		"unset":   "",
		"missing": filepath.Join(t.TempDir(), "no-such-shell"),
	} {
		t.Run(name, func(t *testing.T) {
			result := runCfVault(t, append(setupTokenProfile(t), "SHELL="+shell), "exec", "tokenprofile")

			if result.ExitCode == 0 {
				t.Fatalf("expected non-zero exit, got 0\nstdout: %s", result.Stdout)
			}
			if strings.Contains(result.Stderr, "panic") {
				t.Fatalf("expected an error rather than a panic, got stderr=%q", result.Stderr)
			}
			if shell == "" && !strings.Contains(result.Stderr, "SHELL") {
				t.Errorf("expected error naming SHELL, got stderr=%q", result.Stderr)
			}
			if shell != "" && !strings.Contains(result.Stderr, shell) {
				t.Errorf("expected error naming %s, got stderr=%q", shell, result.Stderr)
			}
		})
	}
}

func TestIntegration_Exec_CommandThatCannotStart(t *testing.T) {
	// Executable, so it passes the PATH lookup, but not a valid binary or
	// script, so replacing the process with it fails.
	notABinary := filepath.Join(t.TempDir(), "not-a-binary")
	if err := os.WriteFile(notABinary, []byte{0x00, 0x01, 0x02}, 0o755); err != nil {
		t.Fatal(err)
	}

	result := runCfVault(t, setupTokenProfile(t), "exec", "tokenprofile", "--", notABinary)

	if result.ExitCode == 0 {
		t.Fatalf("expected non-zero exit when the command cannot start, got 0\nstderr: %s", result.Stderr)
	}
	if !strings.Contains(result.Stderr, notABinary) {
		t.Errorf("expected error naming the command, got stderr=%q", result.Stderr)
	}
}

func TestIntegration_Exec_ExecutableNotFound(t *testing.T) {
	result := runCfVault(t, setupTokenProfile(t), "exec", "tokenprofile", "--", "cf-vault-no-such-command")

	if result.ExitCode == 0 {
		t.Fatalf("expected non-zero exit, got 0")
	}
	if !strings.Contains(result.Stderr, "'cf-vault-no-such-command'") {
		t.Errorf("expected error naming the missing executable, got stderr=%q", result.Stderr)
	}
}

// tokenCreation is a POST /user/tokens request received by the mock API.
type tokenCreation struct {
	header http.Header
	body   map[string]interface{}
}

// setupShortLivedProfile returns the env for an isolated test install holding
// a short lived token profile named "shortlived", with the Cloudflare API
// replaced by a mock that answers token creation with tokenValue. Requests
// the mock receives are sent on the returned channel.
func setupShortLivedProfile(t *testing.T, tokenValue string) ([]string, <-chan tokenCreation) {
	t.Helper()

	created := make(chan tokenCreation, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/user/tokens" {
			http.NotFound(w, r)
			return
		}
		var body map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		created <- tokenCreation{header: r.Header.Clone(), body: body}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success":  true,
			"errors":   []interface{}{},
			"messages": []interface{}{},
			"result":   map[string]interface{}{"id": "short-lived-id", "value": tokenValue},
		})
	}))
	t.Cleanup(srv.Close)

	configDir, keyringDir, envVars, cleanup := setupTestEnv(t)
	t.Cleanup(cleanup)

	writeConfig(t, configDir, `
[profiles]
  [profiles.shortlived]
    auth_type = "api_token"
    session_duration = "15m"

    [[profiles.shortlived.policies]]
      effect = "allow"

      [[profiles.shortlived.policies.permission_groups]]
        id = "c8fed203ed3043cba015a93ad1616f1f"
        name = "Zone Read"

      [profiles.shortlived.policies.resources]
        "com.cloudflare.api.account.zone.*" = "*"
`)
	writeKeyringItem(t, keyringDir, "shortlived-api_token", []byte(testAPIToken))
	return append(envVars, "CLOUDFLARE_BASE_URL="+srv.URL), created
}

func TestIntegration_Exec_ShortLivedToken(t *testing.T) {
	const shortLived = "cfut_" + testAPIToken + "0a1b2c3d"
	envVars, created := setupShortLivedProfile(t, shortLived)

	result := runCfVault(t, envVars, "exec", "shortlived", "--", "env")

	if result.ExitCode != 0 {
		t.Fatalf("expected exit 0, got %d\nstderr: %s", result.ExitCode, result.Stderr)
	}
	if !strings.Contains(result.Stdout, "CLOUDFLARE_API_TOKEN="+shortLived+"\n") {
		t.Errorf("expected the short lived token in the environment, got:\n%s", result.Stdout)
	}
	if got := (<-created).header.Get("Authorization"); got != "Bearer "+testAPIToken {
		t.Errorf("token created with Authorization %q, want the profile's token", got)
	}
}

func TestIntegration_Exec_ShortLivedTokenWithoutValue(t *testing.T) {
	envVars, _ := setupShortLivedProfile(t, "")

	result := runCfVault(t, envVars, "exec", "shortlived", "--", "env")

	if result.ExitCode == 0 {
		t.Fatalf("expected non-zero exit when no token value is returned, got 0\nstdout: %s", result.Stdout)
	}
	if strings.Contains(result.Stdout, "CLOUDFLARE_VAULT_SESSION=") {
		t.Errorf("expected the command not to run, got stdout:\n%s", result.Stdout)
	}
}

func TestIntegration_Exec_UnusableShortLivedProfile(t *testing.T) {
	tests := map[string]struct {
		config string
		want   string
	}{
		"no policies": {
			config: `
[profiles.shortlived]
  auth_type = "api_token"
  session_duration = "15m"
`,
			want: "no policies",
		},
		"zero session duration": {
			config: `
[profiles.shortlived]
  auth_type = "api_token"
  session_duration = "0s"

  [[profiles.shortlived.policies]]
    effect = "allow"
    [[profiles.shortlived.policies.permission_groups]]
      id = "c8fed203ed3043cba015a93ad1616f1f"
    [profiles.shortlived.policies.resources]
      "com.cloudflare.api.account.zone.*" = "*"
`,
			want: "session_duration",
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			// No credential is stored, so failing on the config proves it was
			// checked before the keyring was touched.
			configDir, _, envVars, cleanup := setupTestEnv(t)
			defer cleanup()
			writeConfig(t, configDir, tt.config)

			result := runCfVault(t, envVars, "exec", "shortlived", "--", "env")

			if result.ExitCode == 0 {
				t.Fatalf("expected non-zero exit, got 0\nstdout: %s", result.Stdout)
			}
			if !strings.Contains(result.Stderr, tt.want) {
				t.Errorf("expected error mentioning %q, got stderr=%q", tt.want, result.Stderr)
			}
		})
	}
}
