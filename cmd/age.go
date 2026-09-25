package cmd

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

// yubikeyRecipientRE matches an age-plugin-yubikey recipient anywhere in text.
// The plugin emits the recipient on stderr and (padded) in stdout comments;
// this regex lets us pick it up from either source.
var yubikeyRecipientRE = regexp.MustCompile(`age1yubikey1[0-9a-z]+`)

// Supported age-based secret backends. Each stores the credential as an age
// ciphertext file; the underlying age identity is what differs — hardware
// (Secure Enclave, YubiKey) rather than a software passphrase.
const (
	secretBackendAgeSE      = "age-se"
	secretBackendAgeYubikey = "age-yubikey"
)

// ageIdentityPath returns the identity file for a given age backend. A single
// identity is reused across all profiles bound to that backend.
func ageIdentityPath(configDir, backend string) string {
	switch backend {
	case secretBackendAgeSE:
		return filepath.Join(configDir, "identity-se.txt")
	case secretBackendAgeYubikey:
		return filepath.Join(configDir, "identity-yubikey.txt")
	}
	return ""
}

// ageSecretPath returns the ciphertext location for a profile. Filenames are
// backend-agnostic; profile.SecretBackend tells us which identity to decrypt with.
func ageSecretPath(configDir, profileName string) string {
	return filepath.Join(configDir, "secrets", profileName+".age")
}

// ensureAgeIdentity returns the recipient (public key) for the given backend's
// identity, bootstrapping the identity file on first use where possible.
func ensureAgeIdentity(configDir, backend string) (string, error) {
	switch backend {
	case secretBackendAgeSE:
		return ensureSEIdentity(configDir)
	case secretBackendAgeYubikey:
		return ensureYubikeyIdentity(configDir)
	}
	return "", fmt.Errorf("unknown age backend %q", backend)
}

// ensureSEIdentity generates a Secure Enclave age identity on first use — no
// user interaction is required beyond the Touch ID prompt on subsequent decrypts.
func ensureSEIdentity(configDir string) (string, error) {
	idPath := ageIdentityPath(configDir, secretBackendAgeSE)
	if _, err := os.Stat(idPath); os.IsNotExist(err) {
		if _, err := exec.LookPath("age-plugin-se"); err != nil {
			return "", fmt.Errorf("age-plugin-se not found on PATH; install it (`brew install age-plugin-se`) or place an existing identity file at %s", idPath)
		}
		if err := os.MkdirAll(filepath.Dir(idPath), 0o700); err != nil {
			return "", err
		}
		cmd := exec.Command("age-plugin-se", "keygen", "-o", idPath)
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return "", fmt.Errorf("age-plugin-se keygen failed: %w", err)
		}
		_ = os.Chmod(idPath, 0o600)
	}
	return readAgeRecipient(idPath)
}

// ensureYubikeyIdentity resolves the recipient for a YubiKey-backed age identity.
// YubiKey enrollment is interactive (slot, PIN/touch policies), so we don't
// silently generate one — we either use the identity file the user has already
// placed, or fall back to `age-plugin-yubikey --identity` if there's exactly one
// on-key identity available and cache its recipient locally.
func ensureYubikeyIdentity(configDir string) (string, error) {
	idPath := ageIdentityPath(configDir, secretBackendAgeYubikey)
	if _, err := os.Stat(idPath); err == nil {
		return readAgeRecipient(idPath)
	}

	if _, err := exec.LookPath("age-plugin-yubikey"); err != nil {
		return "", fmt.Errorf("age-plugin-yubikey not found on PATH; install it (`brew install age-plugin-yubikey`) and either run `age-plugin-yubikey --generate` to enroll a new key, or place an existing identity file at %s", idPath)
	}

	cmd := exec.Command("age-plugin-yubikey", "--identity")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("`age-plugin-yubikey --identity` failed (is a YubiKey plugged in?); if this is a fresh key, run `age-plugin-yubikey --generate` first: %w\n%s", err, stderr.String())
	}

	if strings.Count(stdout.String(), "AGE-PLUGIN-YUBIKEY-") > 1 {
		return "", fmt.Errorf("multiple YubiKey identities detected — pick one and save its identity block to %s", idPath)
	}
	if !strings.Contains(stdout.String(), "AGE-PLUGIN-YUBIKEY-") {
		return "", fmt.Errorf("no YubiKey identity found; run `age-plugin-yubikey --generate` to enroll one, then re-run this command")
	}

	// age-plugin-yubikey emits the recipient on stderr and in padded stdout
	// comments; search both, then persist a self-consistent identity file with a
	// canonical `# recipient:` header so subsequent reads round-trip cleanly.
	recipient := yubikeyRecipientRE.FindString(stderr.String() + "\n" + stdout.String())
	if recipient == "" {
		return "", fmt.Errorf("could not extract age1yubikey1… recipient from `age-plugin-yubikey --identity` output")
	}

	if err := os.MkdirAll(filepath.Dir(idPath), 0o700); err != nil {
		return "", err
	}
	body := fmt.Sprintf("# recipient: %s\n%s", recipient, stdout.String())
	if err := os.WriteFile(idPath, []byte(body), 0o600); err != nil {
		return "", fmt.Errorf("failed to cache YubiKey identity at %s: %w", idPath, err)
	}
	return recipient, nil
}

// readAgeRecipient extracts the recipient from an age identity file. Both
// age-plugin-se and age-plugin-yubikey emit it as a comment line — SE uses a
// tight `# public key: …` and YubiKey uses a padded `#    Recipient: …` — so
// strip the leading `#` and internal whitespace before matching.
func readAgeRecipient(idPath string) (string, error) {
	f, err := os.Open(idPath)
	if err != nil {
		return "", err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "#") {
			continue
		}
		body := strings.TrimSpace(strings.TrimPrefix(line, "#"))
		lowered := strings.ToLower(body)
		for _, prefix := range []string{"public key:", "recipient:"} {
			if strings.HasPrefix(lowered, prefix) {
				rec := strings.TrimSpace(body[len(prefix):])
				if rec == "" {
					return "", fmt.Errorf("empty recipient on `# %s` line in %s", prefix, idPath)
				}
				return rec, nil
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	return "", fmt.Errorf("no `# public key:` or `# recipient:` line found in %s", idPath)
}

// encryptWithAge writes an age-encrypted copy of plaintext to outPath.
func encryptWithAge(recipient, outPath string, plaintext []byte) error {
	if _, err := exec.LookPath("age"); err != nil {
		return fmt.Errorf("age not found on PATH; install it (`brew install age`)")
	}
	if err := os.MkdirAll(filepath.Dir(outPath), 0o700); err != nil {
		return err
	}
	cmd := exec.Command("age", "-r", recipient, "-o", outPath)
	cmd.Stdin = bytes.NewReader(plaintext)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("age encryption failed: %w", err)
	}
	return os.Chmod(outPath, 0o600)
}

// decryptWithAge decrypts the ciphertext at inPath. The invocation of age
// shells out to the appropriate plugin (SE or YubiKey), which surfaces the
// Touch ID or hardware-touch prompt.
func decryptWithAge(identityPath, inPath string) ([]byte, error) {
	if _, err := exec.LookPath("age"); err != nil {
		return nil, fmt.Errorf("age not found on PATH; install it (`brew install age`)")
	}
	if _, err := os.Stat(inPath); err != nil {
		return nil, fmt.Errorf("secret ciphertext missing at %s: %w", inPath, err)
	}
	cmd := exec.Command("age", "-d", "-i", identityPath, inPath)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("age decryption failed: %w", err)
	}
	return out.Bytes(), nil
}
