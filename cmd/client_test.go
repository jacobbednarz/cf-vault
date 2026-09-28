package cmd

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestNewClient_SendsOnlyProfileCredentials guards against the SDK's habit of
// adding credentials from CLOUDFLARE_* variables to every request. A stale
// one exported in the calling shell must not ride along with the profile's.
func TestNewClient_SendsOnlyProfileCredentials(t *testing.T) {
	tests := map[string]struct {
		authType, authValue, email string
		want                       map[string]string
	}{
		"api token": {
			authType:  authTypeAPIToken,
			authValue: "profile-token",
			want:      map[string]string{"Authorization": "Bearer profile-token"},
		},
		"api key": {
			authType:  authTypeAPIKey,
			authValue: "profile-key",
			email:     "profile@example.com",
			want:      map[string]string{"X-Auth-Key": "profile-key", "X-Auth-Email": "profile@example.com"},
		},
	}
	authHeaders := []string{"Authorization", "X-Auth-Key", "X-Auth-Email", "X-Auth-User-Service-Key"}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			var got http.Header
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				got = r.Header.Clone()
				w.Header().Set("Content-Type", "application/json")
				w.Write([]byte(`{"success":true,"errors":[],"messages":[],"result":{"id":"user-123"}}`))
			}))
			t.Cleanup(srv.Close)

			t.Setenv("CLOUDFLARE_BASE_URL", srv.URL)
			t.Setenv("CLOUDFLARE_API_TOKEN", "stale-token")
			t.Setenv("CLOUDFLARE_API_KEY", "stale-key")
			t.Setenv("CLOUDFLARE_EMAIL", "stale@example.com")
			t.Setenv("CLOUDFLARE_API_USER_SERVICE_KEY", "stale-service-key")

			if _, err := newClient(tt.authValue, tt.authType, tt.email).User.Get(context.Background()); err != nil {
				t.Fatal(err)
			}

			for _, h := range authHeaders {
				if got.Get(h) != tt.want[h] {
					t.Errorf("%s = %q, want %q", h, got.Get(h), tt.want[h])
				}
			}
		})
	}
}
