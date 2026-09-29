package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const removeTestConfig = `
[profiles]
  [profiles.example]
    auth_type = "api_token"
  [profiles.other]
    auth_type = "api_token"
`

func TestIntegration_Remove_KeyringProfile(t *testing.T) {
	configDir, keyringDir, envVars, cleanup := setupTestEnv(t)
	defer cleanup()

	writeConfig(t, configDir, removeTestConfig)
	writeKeyringItem(t, keyringDir, "example-"+authTypeAPIToken, []byte(testAPIToken))
	writeKeyringItem(t, keyringDir, "other-"+authTypeAPIToken, []byte(testAPIToken))

	result := runCfVault(t, envVars, "remove", "example", "--"+flagForce)

	if result.ExitCode != 0 {
		t.Fatalf("expected exit 0, got %d\nstdout: %s\nstderr: %s", result.ExitCode, result.Stdout, result.Stderr)
	}
	if !strings.Contains(result.Stdout, "still valid at Cloudflare") {
		t.Errorf("expected a reminder that the credential is still valid, got stdout=%q", result.Stdout)
	}
	profiles := readTestConfig(t, configDir).Profiles
	if _, ok := profiles["example"]; ok {
		t.Error("expected the profile to be removed from the config")
	}
	if _, ok := profiles["other"]; !ok {
		t.Error("expected the other profile to be kept")
	}
	if _, ok := readKeyringItem(t, keyringDir, "example-"+authTypeAPIToken); ok {
		t.Error("expected the profile's credential to be removed from the keyring")
	}
	if _, ok := readKeyringItem(t, keyringDir, "other-"+authTypeAPIToken); !ok {
		t.Error("expected the other profile's credential to be kept")
	}
}

func TestIntegration_Remove_AgeProfile(t *testing.T) {
	configDir, _, envVars, cleanup := setupTestEnv(t)
	defer cleanup()

	writeConfig(t, configDir, `
[profiles]
  [profiles.example]
    auth_type = "api_token"
    secret_backend = "`+secretBackendAgeSE+`"
`)
	secretPath := ageSecretPath(configDir, "example")
	if err := os.MkdirAll(filepath.Dir(secretPath), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(secretPath, []byte("ciphertext"), 0600); err != nil {
		t.Fatal(err)
	}

	result := runCfVault(t, envVars, "remove", "example", "--"+flagForce)

	if result.ExitCode != 0 {
		t.Fatalf("expected exit 0, got %d\nstdout: %s\nstderr: %s", result.ExitCode, result.Stdout, result.Stderr)
	}
	if _, ok := readTestConfig(t, configDir).Profiles["example"]; ok {
		t.Error("expected the profile to be removed from the config")
	}
	if _, err := os.Stat(secretPath); !os.IsNotExist(err) {
		t.Errorf("expected the encrypted credential to be removed, stat err = %v", err)
	}
}

// A profile whose credential is already gone, such as after an earlier run
// deleted it but failed to save the config, must still be removable.
func TestIntegration_Remove_CredentialAlreadyGone(t *testing.T) {
	configDir, _, envVars, cleanup := setupTestEnv(t)
	defer cleanup()

	writeConfig(t, configDir, removeTestConfig)

	result := runCfVault(t, envVars, "remove", "example", "--"+flagForce)

	if result.ExitCode != 0 {
		t.Fatalf("expected exit 0, got %d\nstdout: %s\nstderr: %s", result.ExitCode, result.Stdout, result.Stderr)
	}
	if _, ok := readTestConfig(t, configDir).Profiles["example"]; ok {
		t.Error("expected the profile to be removed from the config")
	}
}

// When the credential can't be removed the profile must be kept, so it still
// leads to the credential and `remove` can be retried.
func TestIntegration_Remove_CredentialRemovalFails(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	configDir, _, envVars, cleanup := setupTestEnv(t)
	defer cleanup()

	writeConfig(t, configDir, `
[profiles]
  [profiles.example]
    auth_type = "api_token"
    secret_backend = "`+secretBackendAgeSE+`"
`)
	secretPath := ageSecretPath(configDir, "example")
	secretsDir := filepath.Dir(secretPath)
	if err := os.MkdirAll(secretsDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(secretPath, []byte("ciphertext"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(secretsDir, 0500); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(secretsDir, 0700)

	result := runCfVault(t, envVars, "remove", "example", "--"+flagForce)

	if result.ExitCode == 0 {
		t.Fatalf("expected non-zero exit, got 0\nstdout: %s\nstderr: %s", result.Stdout, result.Stderr)
	}
	if _, ok := readTestConfig(t, configDir).Profiles["example"]; !ok {
		t.Error("expected the profile to be kept when its credential couldn't be removed")
	}
	if _, err := os.Stat(secretPath); err != nil {
		t.Errorf("expected the encrypted credential to be left in place, stat err = %v", err)
	}
}

func TestIntegration_Remove_RequiresConfirmationWithoutTerminal(t *testing.T) {
	configDir, keyringDir, envVars, cleanup := setupTestEnv(t)
	defer cleanup()

	writeConfig(t, configDir, removeTestConfig)
	writeKeyringItem(t, keyringDir, "example-"+authTypeAPIToken, []byte(testAPIToken))

	// Piped input must not be taken as the answer to a confirmation prompt.
	result := runCfVaultWithStdin(t, envVars, strings.NewReader("y\n"), "remove", "example")

	if result.ExitCode == 0 {
		t.Fatalf("expected non-zero exit, got 0\nstdout: %s\nstderr: %s", result.Stdout, result.Stderr)
	}
	if !strings.Contains(result.Stderr, errRemoveNeedsConfirmation.Error()) {
		t.Errorf("expected an error asking for --%s, got stderr=%q", flagForce, result.Stderr)
	}
	if _, ok := readTestConfig(t, configDir).Profiles["example"]; !ok {
		t.Error("expected the profile to be kept")
	}
	if _, ok := readKeyringItem(t, keyringDir, "example-"+authTypeAPIToken); !ok {
		t.Error("expected the credential to be kept")
	}
}

func TestIntegration_Remove_ProfileNotFound(t *testing.T) {
	configDir, _, envVars, cleanup := setupTestEnv(t)
	defer cleanup()

	writeConfig(t, configDir, removeTestConfig)

	result := runCfVault(t, envVars, "remove", "missing", "--"+flagForce)

	if result.ExitCode == 0 {
		t.Fatalf("expected non-zero exit, got 0\nstdout: %s\nstderr: %s", result.Stdout, result.Stderr)
	}
	if !strings.Contains(result.Stderr, `no profile matching "missing"`) {
		t.Errorf("expected a profile not found error, got stderr=%q", result.Stderr)
	}
	if got := len(readTestConfig(t, configDir).Profiles); got != 2 {
		t.Errorf("expected both profiles to be kept, got %d", got)
	}
}

func TestIntegration_Remove_RejectsUnusableArgs(t *testing.T) {
	tests := map[string]struct {
		args []string
		want string
	}{
		"missing profile":  {[]string{"remove", "--" + flagForce}, errProfileArgRequired.Error()},
		"extra arguments":  {[]string{"remove", "example", "other", "--" + flagForce}, "accepts 1 arg(s)"},
		"invalid name":     {[]string{"remove", " example ", "--" + flagForce}, "is invalid"},
		"path in the name": {[]string{"remove", "../example", "--" + flagForce}, "is invalid"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			configDir, _, envVars, cleanup := setupTestEnv(t)
			defer cleanup()

			// A hand edited config can hold any name. One that is a path
			// must be refused before it is joined into the secret's path,
			// or removing it would delete a file outside the secrets dir.
			writeConfig(t, configDir, removeTestConfig+`
  [profiles."../example"]
    auth_type = "api_token"
    secret_backend = "`+secretBackendAgeSE+`"
`)
			outside := filepath.Join(configDir, "example"+ageSecretFileExt)
			if err := os.WriteFile(outside, []byte("not a secret"), 0600); err != nil {
				t.Fatal(err)
			}

			result := runCfVault(t, envVars, tt.args...)

			if result.ExitCode == 0 {
				t.Fatalf("expected non-zero exit, got 0\nstdout: %s\nstderr: %s", result.Stdout, result.Stderr)
			}
			if !strings.Contains(result.Stdout+result.Stderr, tt.want) {
				t.Errorf("expected error containing %q, got stdout=%q stderr=%q", tt.want, result.Stdout, result.Stderr)
			}
			if got := len(readTestConfig(t, configDir).Profiles); got != 3 {
				t.Errorf("expected every profile to be kept, got %d", got)
			}
			if _, err := os.Stat(outside); err != nil {
				t.Errorf("expected the file outside the secrets dir to be left alone, stat err = %v", err)
			}
		})
	}
}

func TestConfirmRemoval(t *testing.T) {
	tests := map[string]bool{
		"y\n":       true,
		"yes\n":     true,
		"Y\n":       true,
		"  YES  \n": true,
		"yes":       true,
		"\n":        false,
		"":          false,
		"n\n":       false,
		"no\n":      false,
		"yess\n":    false,
		"y es\n":    false,
		"no\nyes\n": false,
	}
	for answer, want := range tests {
		t.Run(answer, func(t *testing.T) {
			var out bytes.Buffer
			if got := confirmRemoval("example", strings.NewReader(answer), &out); got != want {
				t.Errorf("confirmRemoval(%q) = %v, want %v", answer, got, want)
			}
			if !strings.Contains(out.String(), `"example"`) {
				t.Errorf("expected the prompt to name the profile, got %q", out.String())
			}
		})
	}
}
