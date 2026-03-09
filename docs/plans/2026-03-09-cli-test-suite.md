# CLI Test Suite Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add automated CLI tests covering `version`, `list`, `exec`, and `add` so no manual testing is needed for basic coverage.

**Architecture:** Unit tests (same `package cmd`) cover pure functions (`determineAuthType`, `environ`). A subprocess integration suite in `cmd/integration_test.go` builds the binary once in `TestMain`, then runs it as a subprocess with isolated temp dirs for config and keyring (using the `file` backend via `CF_VAULT_FILE_PASSPHRASE`). All tests run with `go test -v -race ./...`.

**Tech Stack:** Go `testing`, `os/exec`, `bytes`, `99designs/keyring` (file backend), standard `go build`.

---

### Task 1: Unit tests for `determineAuthType`

**Files:**
- Create: `cmd/add_test.go`

**Step 1: Write the failing tests**

```go
package cmd

import "testing"

func TestDetermineAuthType_APIToken(t *testing.T) {
	// 40-char alphanumeric+hyphen+underscore = API token
	token := "abcdefghijklmnopqrstuvwxyzABCDEF12345678"
	got, err := determineAuthType(token)
	if err != nil {
		t.Fatal(err)
	}
	if got != "api_token" {
		t.Errorf("expected api_token, got %s", got)
	}
}

func TestDetermineAuthType_APIKey(t *testing.T) {
	// 37-char hex = API key
	key := "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f"
	got, err := determineAuthType(key)
	if err != nil {
		t.Fatal(err)
	}
	if got != "api_key" {
		t.Errorf("expected api_key, got %s", got)
	}
}

func TestDetermineAuthType_Invalid(t *testing.T) {
	_, err := determineAuthType("tooshort")
	if err == nil {
		t.Error("expected error for invalid value, got nil")
	}
}
```

**Step 2: Run test to verify it fails**

```bash
cd /Users/jacob/src/jacobbednarz/cf-vault
go test -v -run TestDetermineAuthType ./cmd/
```

Expected: FAIL with "no test files" or "undefined: determineAuthType" (file doesn't exist yet).
Actually since `determineAuthType` exists in `cmd/add.go`, this should PASS immediately. Verify it does pass.

**Step 3: Run and confirm passing**

```bash
go test -v -run TestDetermineAuthType ./cmd/
```

Expected: PASS for all three subtests.

**Step 4: Commit**

```bash
git add cmd/add_test.go
git commit -m "test: add unit tests for determineAuthType"
```

---

### Task 2: Unit tests for `environ` type

**Files:**
- Create: `cmd/env_test.go`

**Step 1: Write the failing tests**

```go
package cmd

import (
	"testing"
)

func TestEnviron_Set(t *testing.T) {
	e := environ{"FOO=bar"}
	e.Set("BAZ", "qux")
	found := false
	for _, s := range e {
		if s == "BAZ=qux" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected BAZ=qux in environ, got %v", []string(e))
	}
}

func TestEnviron_SetOverwrites(t *testing.T) {
	e := environ{"FOO=bar"}
	e.Set("FOO", "baz")
	for _, s := range e {
		if s == "FOO=bar" {
			t.Error("expected old FOO=bar to be replaced")
		}
	}
	found := false
	for _, s := range e {
		if s == "FOO=baz" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected FOO=baz in environ, got %v", []string(e))
	}
}

func TestEnviron_Unset(t *testing.T) {
	e := environ{"FOO=bar", "BAZ=qux"}
	e.Unset("FOO")
	for _, s := range e {
		if s == "FOO=bar" {
			t.Error("expected FOO=bar to be removed")
		}
	}
	if len(e) != 1 {
		t.Errorf("expected 1 entry, got %d: %v", len(e), []string(e))
	}
}

func TestEnviron_UnsetMissing(t *testing.T) {
	e := environ{"FOO=bar"}
	e.Unset("MISSING") // should not panic
	if len(e) != 1 {
		t.Errorf("expected 1 entry unchanged, got %d", len(e))
	}
}
```

**Step 2: Run to verify tests pass**

```bash
go test -v -run TestEnviron ./cmd/
```

Expected: PASS for all four subtests.

**Step 3: Commit**

```bash
git add cmd/env_test.go
git commit -m "test: add unit tests for environ Set/Unset"
```

---

### Task 3: Integration test infrastructure (TestMain + helpers)

**Files:**
- Create: `cmd/integration_test.go`

**Step 1: Write TestMain and helpers**

```go
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
// sets the relevant env vars, and returns a cleanup function.
// It also sets CF_VAULT_FILE_PASSPHRASE so the file keyring never prompts.
func setupTestEnv(t *testing.T) (configDir string, keyringDir string, envVars []string, cleanup func()) {
	t.Helper()

	tmp, err := os.MkdirTemp("", "cf-vault-test-*")
	if err != nil {
		t.Fatal(err)
	}

	configDir = filepath.Join(tmp, "config")
	keyringDir = filepath.Join(tmp, "data", "cf-vault", "keys")

	if err := os.MkdirAll(configDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(keyringDir, 0700); err != nil {
		t.Fatal(err)
	}

	envVars = []string{
		"XDG_CONFIG_HOME=" + filepath.Dir(configDir), // parent of "cf-vault" subdir
		"XDG_DATA_HOME=" + filepath.Join(tmp, "data"),
		"CF_VAULT_FILE_PASSPHRASE=test-passphrase",
		// Clear any existing vault session to avoid nesting checks.
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
```

**Step 2: Run to verify it compiles**

```bash
go test -v -run TestMain ./cmd/ 2>&1 | head -20
```

Expected: no compile errors; tests run (and mostly skip or pass trivially since no integration tests yet).

**Step 3: Commit**

```bash
git add cmd/integration_test.go
git commit -m "test: add integration test infrastructure with TestMain and helpers"
```

---

### Task 4: Integration tests for `version` command

**Files:**
- Modify: `cmd/integration_test.go` (append tests)

**Step 1: Write the failing test**

Append to `cmd/integration_test.go`:

```go
func TestIntegration_Version(t *testing.T) {
	result := runCfVault(t, nil, "version")

	if result.ExitCode != 0 {
		t.Fatalf("expected exit 0, got %d\nstderr: %s", result.ExitCode, result.Stderr)
	}

	if !bytes.Contains([]byte(result.Stdout), []byte("cf-vault")) {
		t.Errorf("expected 'cf-vault' in output, got: %q", result.Stdout)
	}

	// Format: cf-vault <version> (goX.Y.Z,gc-amd64)
	if !bytes.Contains([]byte(result.Stdout), []byte("(")) {
		t.Errorf("expected version format with parentheses, got: %q", result.Stdout)
	}
}
```

Note: you must also add `"bytes"` to the import block at the top of the file if not already present (it is present from the helpers above).

**Step 2: Run to verify it fails (binary not tested yet)**

```bash
go test -v -run TestIntegration_Version ./cmd/
```

Expected: PASS (binary is built in TestMain, version is straightforward).

**Step 3: Commit**

```bash
git add cmd/integration_test.go
git commit -m "test: add integration test for version command"
```

---

### Task 5: Integration tests for `list` command

**Files:**
- Modify: `cmd/integration_test.go` (append tests)

**Step 1: Write the failing tests**

Append to `cmd/integration_test.go`:

```go
func TestIntegration_List_NoConfig(t *testing.T) {
	configDir, _, envVars, cleanup := setupTestEnv(t)
	defer cleanup()

	// Write an empty config file (no profiles section).
	writeConfig(t, configDir, "")

	result := runCfVault(t, envVars, "list")

	if result.ExitCode != 0 {
		t.Fatalf("expected exit 0, got %d\nstderr: %s", result.ExitCode, result.Stderr)
	}

	if !bytes.Contains([]byte(result.Stdout), []byte("no profiles found")) {
		t.Errorf("expected 'no profiles found' message, got: %q", result.Stdout)
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

	if !bytes.Contains([]byte(result.Stdout), []byte("myprofile")) {
		t.Errorf("expected 'myprofile' in output, got: %q", result.Stdout)
	}
	if !bytes.Contains([]byte(result.Stdout), []byte("api_key")) {
		t.Errorf("expected 'api_key' in output, got: %q", result.Stdout)
	}
	if !bytes.Contains([]byte(result.Stdout), []byte("test@example.com")) {
		t.Errorf("expected email in output, got: %q", result.Stdout)
	}
}

func TestIntegration_List_APITokenProfile(t *testing.T) {
	configDir, _, envVars, cleanup := setupTestEnv(t)
	defer cleanup()

	writeConfig(t, configDir, `
[profiles]
  [profiles.tokenprofile]
    auth_type = "api_token"
`)

	result := runCfVault(t, envVars, "list")

	if result.ExitCode != 0 {
		t.Fatalf("expected exit 0, got %d\nstderr: %s", result.ExitCode, result.Stderr)
	}

	if !bytes.Contains([]byte(result.Stdout), []byte("tokenprofile")) {
		t.Errorf("expected 'tokenprofile' in output, got: %q", result.Stdout)
	}
	if !bytes.Contains([]byte(result.Stdout), []byte("api_token")) {
		t.Errorf("expected 'api_token' in output, got: %q", result.Stdout)
	}
	// Email should be blank for api_token profiles.
	if bytes.Contains([]byte(result.Stdout), []byte("test@example.com")) {
		t.Errorf("email should not appear for api_token profiles, got: %q", result.Stdout)
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

	if !bytes.Contains([]byte(result.Stdout), []byte("profile-one")) {
		t.Errorf("expected 'profile-one' in output, got: %q", result.Stdout)
	}
	if !bytes.Contains([]byte(result.Stdout), []byte("profile-two")) {
		t.Errorf("expected 'profile-two' in output, got: %q", result.Stdout)
	}
}
```

**Step 2: Run to verify**

```bash
go test -v -run TestIntegration_List ./cmd/
```

Expected: all four list tests PASS.

**Step 3: Commit**

```bash
git add cmd/integration_test.go
git commit -m "test: add integration tests for list command"
```

---

### Task 6: Integration tests for `exec` error paths

**Files:**
- Modify: `cmd/integration_test.go` (append tests)

**Step 1: Write the failing tests**

Append to `cmd/integration_test.go`:

```go
func TestIntegration_Exec_MissingProfileArg(t *testing.T) {
	result := runCfVault(t, nil, "exec")

	if result.ExitCode == 0 {
		t.Fatalf("expected non-zero exit, got 0\nstdout: %s", result.Stdout)
	}

	// Cobra prints usage errors to stderr.
	combined := result.Stdout + result.Stderr
	if !bytes.Contains([]byte(combined), []byte("requires a profile argument")) {
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
		t.Fatalf("expected non-zero exit, got 0")
	}

	if !bytes.Contains([]byte(result.Stderr), []byte("nonexistent-profile")) {
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

	// Simulate an existing vault session by setting the env var.
	envVars = append(envVars, "CLOUDFLARE_VAULT_SESSION=existing-session")

	result := runCfVault(t, envVars, "exec", "myprofile", "--", "env")

	if result.ExitCode == 0 {
		t.Fatalf("expected non-zero exit when session is already set, got 0")
	}

	if !bytes.Contains([]byte(result.Stderr), []byte("shouldn't be nested")) {
		t.Errorf("expected nesting error message, got stderr=%q", result.Stderr)
	}
}
```

**Step 2: Run to verify**

```bash
go test -v -run TestIntegration_Exec_Missing ./cmd/
go test -v -run TestIntegration_Exec_ProfileNotFound ./cmd/
go test -v -run TestIntegration_Exec_Nested ./cmd/
```

Expected: all three PASS.

**Step 3: Commit**

```bash
git add cmd/integration_test.go
git commit -m "test: add integration tests for exec command error paths"
```

---

### Task 7: Integration tests for `exec` happy path with file keyring

This task pre-populates the file keyring using the `keyring` library directly, then runs exec as a subprocess.

**Files:**
- Modify: `cmd/integration_test.go` (append tests)

**Step 1: Add keyring helper and happy-path tests**

First, add the necessary import to the `integration_test.go` import block. The file currently imports `bytes`, `fmt`, `os`, `os/exec`, `path/filepath`, `testing`. Add `"github.com/99designs/keyring"` and `"strings"`.

Then append the following helper and tests:

```go
// writeKeyringItem stores a credential in the file keyring at keyringDir.
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

	// Override CLOUDFLARE_VAULT_SESSION to be unset (empty string in envVars
	// doesn't actually unset it on some shells; explicitly remove it).
	filteredEnv := make([]string, 0, len(envVars))
	for _, e := range envVars {
		if !strings.HasPrefix(e, "CLOUDFLARE_VAULT_SESSION=") {
			filteredEnv = append(filteredEnv, e)
		}
	}
	envVars = filteredEnv

	writeConfig(t, configDir, `
[profiles]
  [profiles.testprofile]
    email = "user@example.com"
    auth_type = "api_key"
`)

	// Pre-populate the keyring. Key format: "{profileName}-{authType}"
	writeKeyringItem(t, keyringDir, "testprofile-api_key", []byte("a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f"))

	result := runCfVault(t, envVars, "exec", "testprofile", "--", "env")

	if result.ExitCode != 0 {
		t.Fatalf("expected exit 0, got %d\nstderr: %s", result.ExitCode, result.Stderr)
	}

	if !bytes.Contains([]byte(result.Stdout), []byte("CLOUDFLARE_EMAIL=user@example.com")) {
		t.Errorf("expected CLOUDFLARE_EMAIL in output, got:\n%s", result.Stdout)
	}
	if !bytes.Contains([]byte(result.Stdout), []byte("CF_EMAIL=user@example.com")) {
		t.Errorf("expected CF_EMAIL in output, got:\n%s", result.Stdout)
	}
	if !bytes.Contains([]byte(result.Stdout), []byte("CLOUDFLARE_API_KEY=")) {
		t.Errorf("expected CLOUDFLARE_API_KEY in output, got:\n%s", result.Stdout)
	}
	if !bytes.Contains([]byte(result.Stdout), []byte("CLOUDFLARE_VAULT_SESSION=testprofile")) {
		t.Errorf("expected CLOUDFLARE_VAULT_SESSION=testprofile in output, got:\n%s", result.Stdout)
	}
}

func TestIntegration_Exec_APIToken(t *testing.T) {
	configDir, keyringDir, envVars, cleanup := setupTestEnv(t)
	defer cleanup()

	filteredEnv := make([]string, 0, len(envVars))
	for _, e := range envVars {
		if !strings.HasPrefix(e, "CLOUDFLARE_VAULT_SESSION=") {
			filteredEnv = append(filteredEnv, e)
		}
	}
	envVars = filteredEnv

	writeConfig(t, configDir, `
[profiles]
  [profiles.tokenprofile]
    auth_type = "api_token"
`)

	// A valid 40-char API token.
	writeKeyringItem(t, keyringDir, "tokenprofile-api_token", []byte("abcdefghijklmnopqrstuvwxyzABCDEF12345678"))

	result := runCfVault(t, envVars, "exec", "tokenprofile", "--", "env")

	if result.ExitCode != 0 {
		t.Fatalf("expected exit 0, got %d\nstderr: %s", result.ExitCode, result.Stderr)
	}

	if !bytes.Contains([]byte(result.Stdout), []byte("CLOUDFLARE_API_TOKEN=")) {
		t.Errorf("expected CLOUDFLARE_API_TOKEN in output, got:\n%s", result.Stdout)
	}
	if !bytes.Contains([]byte(result.Stdout), []byte("CF_API_TOKEN=")) {
		t.Errorf("expected CF_API_TOKEN in output, got:\n%s", result.Stdout)
	}
	// Email should NOT be set for api_token profiles.
	if bytes.Contains([]byte(result.Stdout), []byte("CLOUDFLARE_EMAIL=")) {
		t.Errorf("CLOUDFLARE_EMAIL should not be set for api_token profiles, got:\n%s", result.Stdout)
	}
	if !bytes.Contains([]byte(result.Stdout), []byte("CLOUDFLARE_VAULT_SESSION=tokenprofile")) {
		t.Errorf("expected CLOUDFLARE_VAULT_SESSION=tokenprofile in output, got:\n%s", result.Stdout)
	}
}
```

**Step 2: Run to verify**

```bash
go test -v -run TestIntegration_Exec_API ./cmd/
```

Expected: both PASS. If keyring fails to open, check that `CF_VAULT_FILE_PASSPHRASE` is being passed through correctly.

**Step 3: Commit**

```bash
git add cmd/integration_test.go
git commit -m "test: add integration tests for exec command happy path with file keyring"
```

---

### Task 8: Integration tests for `add` argument validation

**Files:**
- Modify: `cmd/add_test.go` (append tests)

**Step 1: Write the failing tests**

Append to `cmd/add_test.go`:

```go
func TestIntegration_Add_MissingProfileArg(t *testing.T) {
	result := runCfVault(t, nil, "add")

	if result.ExitCode == 0 {
		t.Fatalf("expected non-zero exit for missing profile arg, got 0")
	}

	combined := result.Stdout + result.Stderr
	if !bytes.Contains([]byte(combined), []byte("requires a profile argument")) {
		t.Errorf("expected 'requires a profile argument' in output, got stdout=%q stderr=%q",
			result.Stdout, result.Stderr)
	}
}
```

Also add the required imports to `cmd/add_test.go`:

```go
package cmd

import (
	"bytes"
	"testing"
)
```

**Step 2: Run to verify**

```bash
go test -v -run TestIntegration_Add ./cmd/
```

Expected: PASS.

**Step 3: Run the full test suite**

```bash
go test -v -race ./...
```

Expected: all tests pass, no race conditions.

**Step 4: Commit**

```bash
git add cmd/add_test.go
git commit -m "test: add integration test for add command argument validation"
```

---

### Task 9: Final verification

**Step 1: Run the full test suite cleanly**

```bash
go test -v -race ./...
```

Expected: all tests pass including the 5 existing path tests and all new tests.

**Step 2: Run gofmt and go vet**

```bash
gofmt -d ./cmd/
go vet ./...
```

Expected: no output (no formatting issues, no vet issues).

**Step 3: Final commit if any cleanup was needed**

```bash
git add -A
git commit -m "test: final cleanup of CLI test suite"
```

---

## Notes for Implementer

- The `setupTestEnv` helper sets `XDG_CONFIG_HOME` to the **parent** of the `cf-vault` subdir (i.e., the temp `config/` dir's parent), because `resolveConfigDir` appends `cf-vault` to `XDG_CONFIG_HOME`. So `configDir` returned from `setupTestEnv` is `<tmp>/config/cf-vault` and `XDG_CONFIG_HOME` is `<tmp>/config`.
- The file keyring key format matches what `exec.go` uses: `fmt.Sprintf("%s-%s", profileName, profile.AuthType)`.
- The `CLOUDFLARE_VAULT_SESSION=` entry in `envVars` from `setupTestEnv` sets it to empty string. For exec happy path tests, filter it out entirely using the `strings.HasPrefix` loop shown in Task 7.
- `syscall.Exec` replaces the process — output from the executed command (`env`) flows to the subprocess's stdout, which `runCfVault` captures correctly.
- If `go test` runs from the `cmd/` directory, the `go build ../` in TestMain builds from the module root correctly.
