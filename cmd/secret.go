package cmd

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/99designs/keyring"
)

// secretStore holds the credential of a single profile.
type secretStore interface {
	Get() ([]byte, error)
	Set(secret []byte) error
	// Delete removes the credential. One that is already gone is not an error.
	Delete() error
}

// openSecretStore returns the store holding the credential of the named
// profile, as selected by its `secret_backend`.
func openSecretStore(configDir, profileName string, p profile) (secretStore, error) {
	if p.SecretBackend == "" {
		ring, err := openKeyring()
		if err != nil {
			return nil, fmt.Errorf(errFmtOpenKeyring, err)
		}
		return keyringStore{ring: ring, key: profileName + "-" + p.AuthType}, nil
	}

	backend, ok := ageBackends[p.SecretBackend]
	if !ok {
		return nil, fmt.Errorf(errFmtUnknownSecretBackend, profileName, p.SecretBackend, secretBackendAgeSE, secretBackendAgeYubikey)
	}
	return ageStore{
		name:         p.SecretBackend,
		backend:      backend,
		identityPath: filepath.Join(configDir, backend.identityFileName),
		secretPath:   ageSecretPath(configDir, profileName),
	}, nil
}

// sameSecretLocation reports whether two configurations of the same profile
// keep their credential in the same place, so storing one replaces the other.
func sameSecretLocation(a, b profile) bool {
	_, aIsAge := ageBackends[a.SecretBackend]
	_, bIsAge := ageBackends[b.SecretBackend]
	if aIsAge || bIsAge {
		// Every age backend encrypts to the same per-profile file.
		return aIsAge && bIsAge
	}
	// Keyring items are keyed by auth type as well as profile name.
	return a.SecretBackend == b.SecretBackend && a.AuthType == b.AuthType
}

// keyringStore keeps the credential in the operating system keyring, or the
// file keyring when that is selected with CF_VAULT_BACKEND.
type keyringStore struct {
	ring keyring.Keyring
	key  string
}

func (s keyringStore) Get() ([]byte, error) {
	item, err := s.ring.Get(s.key)
	if err != nil {
		return nil, fmt.Errorf(errFmtGetKeyringItem, err)
	}
	return item.Data, nil
}

func (s keyringStore) Set(secret []byte) error {
	if err := s.ring.Set(keyring.Item{Key: s.key, Data: secret}); err != nil {
		return fmt.Errorf(errFmtAddKeyringItem, err)
	}
	return nil
}

func (s keyringStore) Delete() error {
	// The file backend reports a missing item as the underlying fs error
	// rather than keyring.ErrKeyNotFound.
	err := s.ring.Remove(s.key)
	if err != nil && !errors.Is(err, keyring.ErrKeyNotFound) && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf(errFmtRemoveKeyringItem, err)
	}
	return nil
}

// ageStore keeps the credential in a file encrypted to a hardware-backed age
// identity.
type ageStore struct {
	name         string
	backend      ageBackend
	identityPath string
	secretPath   string
}

func (s ageStore) Get() ([]byte, error) {
	plaintext, err := decryptWithAge(s.identityPath, s.secretPath)
	if err != nil {
		return nil, fmt.Errorf(errFmtDecryptAgeBackend, s.name, err)
	}
	return plaintext, nil
}

func (s ageStore) Set(secret []byte) error {
	recipient, err := s.backend.ensureIdentity(s.identityPath)
	if err != nil {
		return err
	}
	return encryptWithAge(recipient, s.secretPath, secret)
}

func (s ageStore) Delete() error {
	if err := os.Remove(s.secretPath); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}
