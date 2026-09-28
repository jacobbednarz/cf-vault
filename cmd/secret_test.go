package cmd

import (
	"errors"
	"testing"

	"github.com/99designs/keyring"
)

// keychainLikeRing behaves like the macOS keychain backend: Remove reports a
// missing item with its own error rather than keyring.ErrKeyNotFound, while
// GetMetadata does translate it.
type keychainLikeRing struct {
	keyring.Keyring
	items     map[string]bool
	removeErr error
}

func (r *keychainLikeRing) Remove(key string) error {
	if r.removeErr != nil {
		return r.removeErr
	}
	if !r.items[key] {
		return errors.New("the specified item could not be found in the keychain")
	}
	delete(r.items, key)
	return nil
}

func (r *keychainLikeRing) GetMetadata(key string) (keyring.Metadata, error) {
	if !r.items[key] {
		return keyring.Metadata{}, keyring.ErrKeyNotFound
	}
	return keyring.Metadata{}, nil
}

func TestKeyringStoreDelete(t *testing.T) {
	t.Run("already gone", func(t *testing.T) {
		store := keyringStore{ring: &keychainLikeRing{items: map[string]bool{}}, key: "work-api_key"}
		if err := store.Delete(); err != nil {
			t.Errorf("deleting a missing item: got %v, want nil", err)
		}
	})
	t.Run("already gone from the file keyring", func(t *testing.T) {
		store := keyringStore{ring: openTestKeyring(t, t.TempDir()), key: "work-api_key"}
		if err := store.Delete(); err != nil {
			t.Errorf("deleting a missing item: got %v, want nil", err)
		}
	})
	t.Run("removed", func(t *testing.T) {
		ring := &keychainLikeRing{items: map[string]bool{"work-api_key": true}}
		if err := (keyringStore{ring: ring, key: "work-api_key"}).Delete(); err != nil || ring.items["work-api_key"] {
			t.Errorf("deleting an existing item: got %v, still present = %v", err, ring.items["work-api_key"])
		}
	})
	// A failure to remove an item that is still there must not be mistaken
	// for it already being gone.
	t.Run("remove fails", func(t *testing.T) {
		ring := &keychainLikeRing{items: map[string]bool{"work-api_key": true}, removeErr: errors.New("user interaction is not allowed")}
		if err := (keyringStore{ring: ring, key: "work-api_key"}).Delete(); err == nil {
			t.Error("expected the removal failure to be reported")
		}
	})
}

// Replacing a profile deletes the old credential unless the new one was
// written over it, so getting this wrong either orphans a secret or deletes
// the one just stored.
func TestSameSecretLocation(t *testing.T) {
	keyringKey := profile{AuthType: authTypeAPIKey}
	keyringToken := profile{AuthType: authTypeAPIToken}
	enclaveKey := profile{AuthType: authTypeAPIKey, SecretBackend: secretBackendAgeSE}
	yubikeyToken := profile{AuthType: authTypeAPIToken, SecretBackend: secretBackendAgeYubikey}
	unknown := profile{AuthType: authTypeAPIKey, SecretBackend: "made-up"}

	tests := map[string]struct {
		a, b profile
		want bool
	}{
		"keyring, same auth type":      {keyringKey, keyringKey, true},
		"keyring, different auth type": {keyringKey, keyringToken, false},
		"age backends share a file":    {enclaveKey, yubikeyToken, true},
		"keyring and age":              {keyringKey, enclaveKey, false},
		"age and keyring":              {yubikeyToken, keyringToken, false},
		"unknown backend and keyring":  {unknown, keyringKey, false},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if got := sameSecretLocation(tt.a, tt.b); got != tt.want {
				t.Errorf("sameSecretLocation(%+v, %+v) = %v, want %v", tt.a, tt.b, got, tt.want)
			}
		})
	}
}
