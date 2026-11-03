package cmd

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
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

// TestNewClient_BoundsRetries pins the SDK's default of two retries. v6
// defaulted to ten, with backoff growing to 30 seconds between attempts, which
// left the command hanging for minutes when the API was having trouble.
func TestNewClient_BoundsRetries(t *testing.T) {
	var attempts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		// Retry immediately so the test doesn't wait out the backoff.
		w.Header().Set("Retry-After-Ms", "0")
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	t.Cleanup(srv.Close)
	t.Setenv("CLOUDFLARE_BASE_URL", srv.URL)

	if _, err := newClient("profile-token", authTypeAPIToken, "").User.Get(context.Background()); err == nil {
		t.Fatal("expected an error from a failing API, got nil")
	}
	if got, want := attempts.Load(), int32(3); got != want {
		t.Errorf("attempts = %d, want %d", got, want)
	}
}

// TestCreateToken_StopsAtDeadline guards apiTimeout's assumption that the SDK
// gives up on a retry, however long the API asks it to wait, once the
// context's deadline passes.
func TestCreateToken_StopsAtDeadline(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "3600")
		http.Error(w, "rate limited", http.StatusTooManyRequests)
	}))
	t.Cleanup(srv.Close)
	t.Setenv("CLOUDFLARE_BASE_URL", srv.URL)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := createToken(ctx, newClient("profile-token", authTypeAPIToken, ""), "", "name", time.Now().Add(time.Hour), nil)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want %v", err, context.DeadlineExceeded)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("createToken returned after %s, long after the deadline", elapsed)
	}
}
