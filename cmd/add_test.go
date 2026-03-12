package cmd

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	cloudflare "github.com/cloudflare/cloudflare-go/v6"
	"github.com/cloudflare/cloudflare-go/v6/option"
)

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
	key := "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f67"
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
		return
	}
	if !strings.Contains(err.Error(), "invalid") {
		t.Errorf("unexpected error message: %s", err.Error())
	}
}

func TestIntegration_Add_MissingProfileArg(t *testing.T) {
	result := runCfVault(t, nil, "add")

	if result.ExitCode == 0 {
		t.Fatalf("expected non-zero exit for missing profile arg, got 0\nstdout: %s\nstderr: %s", result.Stdout, result.Stderr)
	}

	combined := result.Stdout + result.Stderr
	if !strings.Contains(combined, "requires a profile argument") {
		t.Errorf("expected 'requires a profile argument' in output, got stdout=%q stderr=%q",
			result.Stdout, result.Stderr)
	}
}

func TestFilterReadGroups_KeepsReadGroups(t *testing.T) {
	groups := []permissionGroup{
		{ID: "1", Name: "DNS Read"},
		{ID: "2", Name: "DNS Write"},
	}
	got := filterReadGroups(groups)
	if len(got) != 1 {
		t.Fatalf("expected 1 group, got %d", len(got))
	}
	if got[0].ID != "1" {
		t.Errorf("expected ID %q, got %q", "1", got[0].ID)
	}
}

func TestFilterReadGroups_MidNameRead(t *testing.T) {
	// strings.Contains is used, so "Read" anywhere in the name matches.
	groups := []permissionGroup{
		{ID: "1", Name: "Magic Firewall Packet Captures - Read PCAPs API"},
	}
	got := filterReadGroups(groups)
	if len(got) != 1 {
		t.Fatalf("expected 1 group for mid-name Read, got %d", len(got))
	}
}

func TestFilterReadGroups_DropsNonRead(t *testing.T) {
	groups := []permissionGroup{
		{ID: "1", Name: "DNS Write"},
		{ID: "2", Name: "Cache Purge"},
	}
	got := filterReadGroups(groups)
	if len(got) != 0 {
		t.Errorf("expected empty result, got %d groups", len(got))
	}
}

func TestFilterReadGroups_Empty(t *testing.T) {
	got := filterReadGroups(nil)
	if len(got) != 0 {
		t.Errorf("expected empty result for nil input, got %d", len(got))
	}
}

// mockPermGroup is a minimal struct matching Cloudflare API permission group shape.
type mockPermGroup struct {
	ID     string   `json:"id"`
	Name   string   `json:"name"`
	Scopes []string `json:"scopes"`
}

// permGroupResponse is the envelope the Cloudflare API wraps results in.
type permGroupResponse struct {
	Success  bool            `json:"success"`
	Errors   []interface{}   `json:"errors"`
	Messages []interface{}   `json:"messages"`
	Result   []mockPermGroup `json:"result"`
}

// newMockPermGroupServer starts an httptest.Server serving GET /user/tokens/permission_groups.
func newMockPermGroupServer(t *testing.T, groups []mockPermGroup) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/user/tokens/permission_groups", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(permGroupResponse{
			Success:  true,
			Errors:   []interface{}{},
			Messages: []interface{}{},
			Result:   groups,
		})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// newTestClient creates a v6 client pointed at baseURL with a dummy API token.
// Retries are disabled so tests fail fast on error responses.
func newTestClient(t *testing.T, baseURL string) *cloudflare.Client {
	t.Helper()
	return cloudflare.NewClient(
		option.WithAPIToken("test-token"),
		option.WithBaseURL(baseURL),
		option.WithMaxRetries(0),
	)
}

// representativeGroups covers all three recognised scopes plus an r2 group (ignored).
var representativeGroups = []mockPermGroup{
	{ID: "acct-dns-read", Name: "DNS Read", Scopes: []string{"com.cloudflare.api.account"}},
	{ID: "acct-dns-write", Name: "DNS Write", Scopes: []string{"com.cloudflare.api.account"}},
	{ID: "zone-dns-read", Name: "DNS Read", Scopes: []string{"com.cloudflare.api.account.zone"}},
	{ID: "zone-dns-write", Name: "DNS Write", Scopes: []string{"com.cloudflare.api.account.zone"}},
	{ID: "user-token-read", Name: "API Tokens Read", Scopes: []string{"com.cloudflare.api.user"}},
	{ID: "user-memb-write", Name: "Memberships Write", Scopes: []string{"com.cloudflare.api.user"}},
	{ID: "r2-read", Name: "R2 Read", Scopes: []string{"com.cloudflare.edge.r2.bucket"}},
}

func TestGeneratePolicy_ReadOnly(t *testing.T) {
	srv := newMockPermGroupServer(t, representativeGroups)
	client := newTestClient(t, srv.URL)

	policies, err := generatePolicy(context.Background(), client, "read-only", "user-123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(policies) != 3 {
		t.Fatalf("expected 3 policies, got %d", len(policies))
	}

	// Each policy must contain only Read groups.
	for _, p := range policies {
		for _, g := range p.PermissionGroups {
			if !strings.Contains(g.Name, "Read") {
				t.Errorf("read-only policy contains non-Read group %q", g.Name)
			}
		}
	}

	// Verify resource strings.
	wantResources := []string{
		"com.cloudflare.api.account.*",
		"com.cloudflare.api.account.zone.*",
		"com.cloudflare.api.user.user-123",
	}
	for i, want := range wantResources {
		if _, ok := policies[i].Resources[want]; !ok {
			t.Errorf("policy[%d]: expected resource key %q, got %v", i, want, policies[i].Resources)
		}
	}

	// R2 group must not appear in any policy.
	for _, p := range policies {
		for _, g := range p.PermissionGroups {
			if g.ID == "r2-read" {
				t.Error("R2 bucket scope group must not appear in any policy")
			}
		}
	}
}

func TestGeneratePolicy_WriteEverything(t *testing.T) {
	srv := newMockPermGroupServer(t, representativeGroups)
	client := newTestClient(t, srv.URL)

	policies, err := generatePolicy(context.Background(), client, "write-everything", "user-456")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(policies) != 3 {
		t.Fatalf("expected 3 policies, got %d", len(policies))
	}

	// Every policy bucket must be non-empty and contain at least one Write group.
	for i, p := range policies {
		if len(p.PermissionGroups) == 0 {
			t.Errorf("policy[%d] has no permission groups", i)
		}
		hasWrite := false
		for _, g := range p.PermissionGroups {
			if strings.Contains(g.Name, "Write") {
				hasWrite = true
			}
		}
		if !hasWrite {
			t.Errorf("policy[%d]: write-everything should include Write groups but none found", i)
		}
	}
}

func TestGeneratePolicy_UnknownType(t *testing.T) {
	srv := newMockPermGroupServer(t, representativeGroups)
	client := newTestClient(t, srv.URL)

	_, err := generatePolicy(context.Background(), client, "superadmin", "user-789")
	if err == nil {
		t.Fatal("expected error for unknown policy type, got nil")
	}
	if !strings.Contains(err.Error(), "read-only") || !strings.Contains(err.Error(), "write-everything") {
		t.Errorf("error should mention valid policy names, got: %v", err)
	}
}

func TestGeneratePolicy_EmptyBucket(t *testing.T) {
	// Only account and user groups — no zone groups — so read-only zone bucket is empty.
	groups := []mockPermGroup{
		{ID: "acct-read", Name: "DNS Read", Scopes: []string{"com.cloudflare.api.account"}},
		{ID: "user-read", Name: "API Tokens Read", Scopes: []string{"com.cloudflare.api.user"}},
	}
	srv := newMockPermGroupServer(t, groups)
	client := newTestClient(t, srv.URL)

	_, err := generatePolicy(context.Background(), client, "read-only", "user-000")
	if err == nil {
		t.Fatal("expected error for empty zone bucket, got nil")
	}
	if !strings.Contains(err.Error(), "empty") || !strings.Contains(err.Error(), "zone=0") {
		t.Errorf("error should mention empty bucket and zone=0, got: %v", err)
	}
}

func TestGeneratePolicy_APIError(t *testing.T) {
	// Server returns 500 for any request.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	client := newTestClient(t, srv.URL)

	_, err := generatePolicy(context.Background(), client, "read-only", "user-err")
	if err == nil {
		t.Fatal("expected error for API 500 response, got nil")
	}
}
