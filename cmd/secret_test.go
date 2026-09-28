package cmd

import "testing"

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
