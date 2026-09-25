package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeIdentity(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "identity.txt")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestReadAgeRecipient_SEStyle(t *testing.T) {
	// age-plugin-se writes a tight `# public key: …` comment.
	path := writeIdentity(t, "# created: 2026-01-01\n# public key: age1se1qgxyz\nAGE-PLUGIN-SE-1ABC\n")
	got, err := readAgeRecipient(path)
	if err != nil {
		t.Fatal(err)
	}
	if got != "age1se1qgxyz" {
		t.Errorf("got %q, want age1se1qgxyz", got)
	}
}

func TestReadAgeRecipient_YubikeyPaddedStyle(t *testing.T) {
	// age-plugin-yubikey pads fields for readability: `#    Recipient: …`.
	path := writeIdentity(t, "#       Serial: 12345, Slot: 1\n#    Recipient: age1yubikey1qabc\nAGE-PLUGIN-YUBIKEY-1XYZ\n")
	got, err := readAgeRecipient(path)
	if err != nil {
		t.Fatal(err)
	}
	if got != "age1yubikey1qabc" {
		t.Errorf("got %q, want age1yubikey1qabc", got)
	}
}

func TestReadAgeRecipient_CanonicalHeader(t *testing.T) {
	// The file cf-vault itself writes for cached YubiKey identities.
	path := writeIdentity(t, "# recipient: age1yubikey1qabc\nAGE-PLUGIN-YUBIKEY-1XYZ\n")
	got, err := readAgeRecipient(path)
	if err != nil {
		t.Fatal(err)
	}
	if got != "age1yubikey1qabc" {
		t.Errorf("got %q, want age1yubikey1qabc", got)
	}
}

func TestReadAgeRecipient_NoComment(t *testing.T) {
	path := writeIdentity(t, "AGE-PLUGIN-YUBIKEY-1XYZ\n")
	_, err := readAgeRecipient(path)
	if err == nil {
		t.Fatal("expected error for identity file with no recipient comment")
	}
	if !strings.Contains(err.Error(), "no `# public key:`") {
		t.Errorf("error should name the missing comment, got: %v", err)
	}
}

func TestReadAgeRecipient_EmptyRecipient(t *testing.T) {
	path := writeIdentity(t, "# recipient:   \nAGE-PLUGIN-YUBIKEY-1XYZ\n")
	_, err := readAgeRecipient(path)
	if err == nil {
		t.Fatal("expected error for empty recipient value")
	}
	if !strings.Contains(err.Error(), "empty recipient") {
		t.Errorf("error should mention empty recipient, got: %v", err)
	}
}

func TestReadAgeRecipient_MissingFile(t *testing.T) {
	_, err := readAgeRecipient(filepath.Join(t.TempDir(), "does-not-exist.txt"))
	if err == nil {
		t.Fatal("expected error for missing identity file")
	}
}
