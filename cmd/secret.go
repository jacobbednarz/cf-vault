package cmd

import (
	"fmt"
	"path/filepath"

	"github.com/99designs/keyring"
)

// secretStore holds the credential of a single profile.
type secretStore interface {
	Get() ([]byte, error)
	Set(secret []byte) error
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
