package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	cloudflare "github.com/cloudflare/cloudflare-go/v6"
	"github.com/cloudflare/cloudflare-go/v6/option"
	"github.com/pelletier/go-toml"
)

func TestDetermineAuthType(t *testing.T) {
	body := "abcdefghijklmnopqrstuvwxyzABCDEF12345678" // 40 chars
	checksum := "0a1b2c3d"
	hex40 := "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"

	cases := map[string]struct {
		value string
		want  string
	}{
		"scannable user token":      {"cfut_" + body + checksum, authTypeAPIToken},
		"scannable account token":   {"cfat_" + body + checksum, authTypeAPIToken},
		"scannable global key":      {"cfk_" + body + checksum, authTypeAPIKey},
		"legacy token":              {body, authTypeAPIToken},
		"legacy token with symbols": {"abcdefghij-klmnopqrst_uvwxyzABCD12345678", authTypeAPIToken},
		"legacy key 37 chars":       {hex40[:37], authTypeAPIKey},
		"legacy key 45 chars":       {hex40 + "c3d4e", authTypeAPIKey},
		"legacy key 40 chars":       {hex40, authTypeAPIKey},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := determineAuthType(tc.value)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Errorf("determineAuthType(%q) = %s, want %s", tc.value, got, tc.want)
			}
		})
	}
}

func TestDetermineAuthType_Invalid(t *testing.T) {
	body := "abcdefghijklmnopqrstuvwxyzABCDEF12345678"
	invalid := map[string]string{
		"empty":                    "",
		"too short":                "tooshort",
		"legacy token too long":    body + "9",
		"legacy key too short":     "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6",
		"legacy key too long":      "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6",
		"scannable body too short": "cfut_" + body[:39],
		"unknown prefix":           "cfxx_" + body + "0a1b2c3d",
		"surrounding whitespace":   " " + body,
		"trailing text":            body + " extra",
	}
	for name, value := range invalid {
		t.Run(name, func(t *testing.T) {
			if got, err := determineAuthType(value); !errors.Is(err, errInvalidAuthValueFormat) {
				t.Errorf("determineAuthType(%q) = (%s, %v), want %v", value, got, err, errInvalidAuthValueFormat)
			}
		})
	}
}

func TestValidateProfileName(t *testing.T) {
	valid := []string{"work", "read-only", "profile.2", "a_b-c.d", "MixedCase123"}
	for _, name := range valid {
		if err := validateProfileName(name); err != nil {
			t.Errorf("expected %q to be valid, got error: %v", name, err)
		}
	}

	invalid := []string{
		"",           // empty
		".hidden",    // leading dot
		"..",         // parent directory
		"../evil",    // traversal
		"foo/bar",    // path separator
		`foo\bar`,    // windows separator
		"foo bar",    // whitespace
		"foo\x00bar", // control character
		"a$b",        // shell metacharacter
	}
	for _, name := range invalid {
		if err := validateProfileName(name); err == nil {
			t.Errorf("expected %q to be rejected, got no error", name)
		}
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

func TestIntegration_Add_RejectsUnusableArgs(t *testing.T) {
	tests := map[string]struct {
		args []string
		want string
	}{
		// A stray argument usually means a mistyped flag or an unquoted
		// name, so saving a profile anyway would hide the mistake.
		"extra arguments": {[]string{"add", "example", "extra"}, "accepts 1 arg(s)"},
		// `exec` looks names up verbatim, so `add` must not quietly save
		// one that differs from what was typed.
		"surrounding whitespace": {[]string{"add", " example "}, "is invalid"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			configDir, _, envVars, cleanup := setupTestEnv(t)
			defer cleanup()

			result := runCfVault(t, append(envVars, envAuthValue+"="+testAPIToken), tt.args...)

			if result.ExitCode == 0 {
				t.Fatalf("expected non-zero exit, got 0\nstdout: %s\nstderr: %s", result.Stdout, result.Stderr)
			}
			if !strings.Contains(result.Stderr, tt.want) {
				t.Errorf("expected error containing %q, got stderr=%q", tt.want, result.Stderr)
			}
			if _, err := os.Stat(filepath.Join(configDir, configFileName)); !os.IsNotExist(err) {
				t.Errorf("expected no config to be written, stat err = %v", err)
			}
		})
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

// Permission groups carry no read/write attribute, only a name, so the read
// template keys off "Read" as a word wherever it appears, but not inside a
// longer word that could name a group granting writes.
func TestFilterReadGroups_ReadAsAWord(t *testing.T) {
	groups := []permissionGroup{
		{ID: "mid-name", Name: "Magic Firewall Packet Captures - Read PCAPs API"},
		{ID: "inside-word", Name: "Load Balancer Readiness Write"},
	}
	got := filterReadGroups(groups)
	if len(got) != 1 || got[0].ID != "mid-name" {
		t.Errorf("got %+v, want only the mid-name Read group", got)
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
	{ID: "acct-token-write", Name: "Account API Tokens Write", Scopes: []string{"com.cloudflare.api.account"}},
	{ID: "zone-dns-read", Name: "DNS Read", Scopes: []string{"com.cloudflare.api.account.zone"}},
	{ID: "zone-dns-write", Name: "DNS Write", Scopes: []string{"com.cloudflare.api.account.zone"}},
	{ID: "user-token-read", Name: "API Tokens Read", Scopes: []string{"com.cloudflare.api.user"}},
	{ID: "user-token-write", Name: "API Tokens Write", Scopes: []string{"com.cloudflare.api.user"}},
	{ID: "user-memb-write", Name: "Memberships Write", Scopes: []string{"com.cloudflare.api.user"}},
	{ID: "r2-read", Name: "R2 Read", Scopes: []string{"com.cloudflare.edge.r2.bucket"}},
}

func TestGeneratePolicy_ReadOnly(t *testing.T) {
	srv := newMockPermGroupServer(t, representativeGroups)
	client := newTestClient(t, srv.URL)

	policies, err := generatePolicy(context.Background(), client, "read-only", "user-123", nil, nil)
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

	policies, err := generatePolicy(context.Background(), client, "write-everything", "user-456", nil, nil)
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

	// No bucket may carry permission to manage API tokens — Cloudflare
	// rejects POST /user/tokens with 1001 when a sub-token would be able to
	// manage other tokens, whether the permission lives in the User or
	// Account scope. Reading tokens is delegable.
	for _, p := range policies {
		for _, g := range p.PermissionGroups {
			if strings.Contains(g.Name, "API Tokens") && !strings.HasSuffix(g.Name, " Read") {
				t.Errorf("policy for %v contains %q, which cannot be delegated to a sub-token", p.Resources, g.Name)
			}
		}
	}

	// Writing everything must not grant less than reading everything.
	readOnly, err := generatePolicy(context.Background(), client, "read-only", "user-456", nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for i, p := range readOnly {
		for _, g := range p.PermissionGroups {
			if !slices.Contains(policies[i].PermissionGroups, g) {
				t.Errorf("read-only grants %q in policy[%d], but write-everything does not", g.Name, i)
			}
		}
	}
}

func TestGeneratePolicy_UnknownType(t *testing.T) {
	srv := newMockPermGroupServer(t, representativeGroups)
	client := newTestClient(t, srv.URL)

	_, err := generatePolicy(context.Background(), client, "superadmin", "user-789", nil, nil)
	if err == nil {
		t.Fatal("expected error for unknown policy type, got nil")
	}
	if !strings.Contains(err.Error(), "read-only") || !strings.Contains(err.Error(), "write-everything") {
		t.Errorf("error should mention valid policy names, got: %v", err)
	}
}

func TestGeneratePolicy_ResourceRestrictions(t *testing.T) {
	const (
		acctA = "01a7362d577a6c3019a474fd6f485823"
		acctB = "9a7806061c88ada191ed06f989cc3dac"
		zoneA = "023e105f4ecef8ad9ca31a8372d0c353"
		zoneB = "353c0d2738a13ac9da8fece4f501e320"
	)

	// Each expected policy pairs its resources with the permission group ID
	// prefix of the bucket it must carry, so a restriction applied to the
	// wrong bucket (e.g. zone resources on account permissions) fails.
	type wantPolicy struct {
		groupPrefix string
		resources   map[string]interface{}
	}
	userPolicy := wantPolicy{"user-", map[string]interface{}{"com.cloudflare.api.user.user-123": "*"}}

	tests := []struct {
		name       string
		accountIDs []string
		zoneIDs    []string
		want       []wantPolicy
	}{
		{
			name: "unrestricted",
			want: []wantPolicy{
				{"acct-", map[string]interface{}{"com.cloudflare.api.account.*": "*"}},
				{"zone-", map[string]interface{}{"com.cloudflare.api.account.zone.*": "*"}},
				userPolicy,
			},
		},
		{
			name:       "accounts scope account policy and nest zones under them",
			accountIDs: []string{acctA, acctB},
			want: []wantPolicy{
				{"acct-", map[string]interface{}{
					"com.cloudflare.api.account." + acctA: "*",
					"com.cloudflare.api.account." + acctB: "*",
				}},
				{"zone-", map[string]interface{}{
					"com.cloudflare.api.account." + acctA: map[string]interface{}{"com.cloudflare.api.account.zone.*": "*"},
					"com.cloudflare.api.account." + acctB: map[string]interface{}{"com.cloudflare.api.account.zone.*": "*"},
				}},
				userPolicy,
			},
		},
		{
			name:    "zones alone drop the account policy",
			zoneIDs: []string{zoneA, zoneB},
			want: []wantPolicy{
				{"zone-", map[string]interface{}{
					"com.cloudflare.api.account.zone." + zoneA: "*",
					"com.cloudflare.api.account.zone." + zoneB: "*",
				}},
				userPolicy,
			},
		},
		{
			name:       "zones take precedence over accounts for the zone policy",
			accountIDs: []string{acctA},
			zoneIDs:    []string{zoneA},
			want: []wantPolicy{
				{"acct-", map[string]interface{}{"com.cloudflare.api.account." + acctA: "*"}},
				{"zone-", map[string]interface{}{"com.cloudflare.api.account.zone." + zoneA: "*"}},
				userPolicy,
			},
		},
	}

	srv := newMockPermGroupServer(t, representativeGroups)
	client := newTestClient(t, srv.URL)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policies, err := generatePolicy(context.Background(), client, "read-only", "user-123", tt.accountIDs, tt.zoneIDs)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(policies) != len(tt.want) {
				t.Fatalf("expected %d policies, got %d: %+v", len(tt.want), len(policies), policies)
			}
			for i, want := range tt.want {
				if !reflect.DeepEqual(policies[i].Resources, want.resources) {
					t.Errorf("policy[%d] resources:\n got  %v\n want %v", i, policies[i].Resources, want.resources)
				}
				for _, g := range policies[i].PermissionGroups {
					if !strings.HasPrefix(g.ID, want.groupPrefix) {
						t.Errorf("policy[%d] carries %q, expected only %s* groups", i, g.ID, want.groupPrefix)
					}
				}
			}
		})
	}
}

func TestValidateResourceIDs(t *testing.T) {
	valid := []string{"01a7362d577a6c3019a474fd6f485823", "023e105f4ecef8ad9ca31a8372d0c353"}
	if err := validateResourceIDs("account", valid); err != nil {
		t.Errorf("expected valid IDs to pass, got %v", err)
	}
	if err := validateResourceIDs("account", nil); err != nil {
		t.Errorf("expected no IDs to pass, got %v", err)
	}

	invalid := []string{
		"",
		"*",
		"01A7362D577A6C3019A474FD6F485823",  // uppercase
		"01a7362d577a6c3019a474fd6f48582",   // 31 chars
		"01a7362d577a6c3019a474fd6f4858233", // 33 chars
		"01a7362d577a6c3019a474fd6f48582g",  // non-hex
		"zone.023e105f4ecef8ad9ca31a8372d0",
	}
	for _, id := range invalid {
		// Pair with a valid ID so a check that only inspects the first entry fails.
		err := validateResourceIDs("zone", []string{valid[0], id})
		if err == nil {
			t.Errorf("expected %q to be rejected", id)
			continue
		}
		if !strings.Contains(err.Error(), "zone ID") {
			t.Errorf("error should name the resource kind, got %v", err)
		}
	}
}

func TestIntegration_Add_ResourceIDsRequireTemplate(t *testing.T) {
	result := runCfVault(t, nil, "add", "example", "--account-id", "01a7362d577a6c3019a474fd6f485823")

	if result.ExitCode == 0 {
		t.Fatalf("expected non-zero exit, got 0\nstdout: %s\nstderr: %s", result.Stdout, result.Stderr)
	}
	if combined := result.Stdout + result.Stderr; !strings.Contains(combined, "can only be used with --profile-template") {
		t.Errorf("expected template requirement error, got stdout=%q stderr=%q", result.Stdout, result.Stderr)
	}
}

func TestIntegration_Add_InvalidZoneID(t *testing.T) {
	result := runCfVault(t, nil, "add", "example", "--profile-template", "read-only", "--session-duration", "15m", "--zone-id", "*")

	if result.ExitCode == 0 {
		t.Fatalf("expected non-zero exit, got 0\nstdout: %s\nstderr: %s", result.Stdout, result.Stderr)
	}
	if combined := result.Stdout + result.Stderr; !strings.Contains(combined, "zone ID") || !strings.Contains(combined, "is invalid") {
		t.Errorf("expected invalid zone ID error, got stdout=%q stderr=%q", result.Stdout, result.Stderr)
	}
}

const (
	testAPIToken = "abcdefghijklmnopqrstuvwxyzABCDEF12345678"
	testAPIKey   = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f67"
)

// readTestConfig decodes the config.toml written by `add`.
func readTestConfig(t *testing.T, configDir string) tomlConfig {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(configDir, configFileName))
	if err != nil {
		t.Fatalf("reading config: %v", err)
	}
	var cfg tomlConfig
	if err := toml.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("decoding config: %v", err)
	}
	return cfg
}

// credentialSource describes how a test hands the authentication value to
// `add` without a terminal.
type credentialSource struct {
	name  string
	stdin func(secret string) io.Reader
	env   func(secret string) []string
	flags []string
}

var nonInteractiveSources = []credentialSource{
	{
		name:  "stdin",
		stdin: func(secret string) io.Reader { return strings.NewReader(secret + "\n") },
		env:   func(string) []string { return nil },
		flags: []string{"--" + flagAuthValueStdin},
	},
	{
		name:  "env",
		stdin: func(string) io.Reader { return nil },
		env:   func(secret string) []string { return []string{envAuthValue + "=" + secret} },
	},
}

func TestIntegration_Add_NonInteractive(t *testing.T) {
	tests := []struct {
		name         string
		secret       string
		email        string
		wantAuthType string
	}{
		{name: "api token without email", secret: testAPIToken, wantAuthType: authTypeAPIToken},
		{name: "api key with email", secret: testAPIKey, email: "user@example.com", wantAuthType: authTypeAPIKey},
	}

	for _, src := range nonInteractiveSources {
		for _, tt := range tests {
			t.Run(src.name+"/"+tt.name, func(t *testing.T) {
				configDir, keyringDir, envVars, cleanup := setupTestEnv(t)
				defer cleanup()

				args := append([]string{"add", "example"}, src.flags...)
				if tt.email != "" {
					args = append(args, "--"+flagEmail, tt.email)
				}
				result := runCfVaultWithStdin(t, append(envVars, src.env(tt.secret)...), src.stdin(tt.secret), args...)

				if result.ExitCode != 0 {
					t.Fatalf("expected exit 0, got %d\nstdout: %s\nstderr: %s", result.ExitCode, result.Stdout, result.Stderr)
				}
				for _, prompt := range []string{promptEmailAddress, promptAuthValue} {
					if strings.Contains(result.Stdout, prompt) {
						t.Errorf("expected no prompt %q, got stdout=%q", prompt, result.Stdout)
					}
				}

				got, ok := readTestConfig(t, configDir).Profiles["example"]
				if !ok {
					t.Fatal("expected profile to be written to config")
				}
				if got.AuthType != tt.wantAuthType || got.Email != tt.email {
					t.Errorf("got auth_type=%q email=%q, want auth_type=%q email=%q", got.AuthType, got.Email, tt.wantAuthType, tt.email)
				}

				// The trailing newline from stdin must not end up in the stored secret.
				stored, ok := readKeyringItem(t, keyringDir, "example-"+tt.wantAuthType)
				if !ok {
					t.Fatal("expected credential to be stored in the keyring")
				}
				if string(stored) != tt.secret {
					t.Errorf("stored secret = %q, want %q", stored, tt.secret)
				}
			})
		}
	}
}

func TestIntegration_Add_APIKeyRequiresEmail(t *testing.T) {
	for _, src := range nonInteractiveSources {
		t.Run(src.name, func(t *testing.T) {
			configDir, keyringDir, envVars, cleanup := setupTestEnv(t)
			defer cleanup()

			args := append([]string{"add", "example"}, src.flags...)
			result := runCfVaultWithStdin(t, append(envVars, src.env(testAPIKey)...), src.stdin(testAPIKey), args...)

			if result.ExitCode == 0 {
				t.Fatalf("expected non-zero exit, got 0\nstdout: %s\nstderr: %s", result.Stdout, result.Stderr)
			}
			if !strings.Contains(result.Stderr, errEmailRequiredForAPIKey.Error()) {
				t.Errorf("expected email requirement error, got stderr=%q", result.Stderr)
			}
			if strings.Contains(result.Stdout, promptEmailAddress) {
				t.Errorf("expected no email prompt, got stdout=%q", result.Stdout)
			}
			if _, err := os.Stat(filepath.Join(configDir, configFileName)); !os.IsNotExist(err) {
				t.Errorf("expected no config to be written, stat err = %v", err)
			}
			if _, ok := readKeyringItem(t, keyringDir, "example-"+authTypeAPIKey); ok {
				t.Error("expected no credential to be stored in the keyring")
			}
		})
	}
}

func TestIntegration_Add_StdinTakesPrecedenceOverEnv(t *testing.T) {
	_, keyringDir, envVars, cleanup := setupTestEnv(t)
	defer cleanup()

	const envToken = "ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwvu87654321"
	result := runCfVaultWithStdin(t,
		append(envVars, envAuthValue+"="+envToken),
		strings.NewReader(testAPIToken),
		"add", "example", "--"+flagAuthValueStdin,
	)

	if result.ExitCode != 0 {
		t.Fatalf("expected exit 0, got %d\nstderr: %s", result.ExitCode, result.Stderr)
	}
	stored, _ := readKeyringItem(t, keyringDir, "example-"+authTypeAPIToken)
	if string(stored) != testAPIToken {
		t.Errorf("stored secret = %q, want the stdin value %q", stored, testAPIToken)
	}
}

// endlessReader never runs out, like `cf-vault add … < /dev/zero`.
type endlessReader struct{}

func (endlessReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'a'
	}
	return len(p), nil
}

func TestIntegration_Add_StdinReadIsBounded(t *testing.T) {
	_, keyringDir, envVars, cleanup := setupTestEnv(t)
	defer cleanup()

	// Reading all of stdin before looking at it would never finish here.
	result := runCfVaultWithStdin(t, envVars, endlessReader{}, "add", "example", "--"+flagAuthValueStdin)

	if result.ExitCode == 0 {
		t.Fatalf("expected non-zero exit, got 0\nstdout: %s", result.Stdout)
	}
	if !strings.Contains(result.Stderr, "too long") {
		t.Errorf("expected an error about the value's length, got stderr=%q", result.Stderr)
	}
	if _, ok := readKeyringItem(t, keyringDir, "example-"+authTypeAPIToken); ok {
		t.Error("expected no credential to be stored")
	}
}

func TestIntegration_Add_NoAuthValueSourceWithoutTerminal(t *testing.T) {
	configDir, _, envVars, cleanup := setupTestEnv(t)
	defer cleanup()

	// Test stdin is the null device, so an unguarded prompt would read EOF
	// rather than hang; asserting the explicit error proves the guard fired.
	result := runCfVault(t, envVars, "add", "example")

	if result.ExitCode == 0 {
		t.Fatalf("expected non-zero exit, got 0\nstdout: %s\nstderr: %s", result.Stdout, result.Stderr)
	}
	if !strings.Contains(result.Stderr, errAuthValueSourceRequired.Error()) {
		t.Errorf("expected missing auth value source error, got stderr=%q", result.Stderr)
	}
	if strings.Contains(result.Stdout, promptEmailAddress) || strings.Contains(result.Stdout, promptAuthValue) {
		t.Errorf("expected no prompts, got stdout=%q", result.Stdout)
	}
	if _, err := os.Stat(filepath.Join(configDir, configFileName)); !os.IsNotExist(err) {
		t.Errorf("expected no config to be written, stat err = %v", err)
	}
}

func TestIntegration_Add_ExistingProfileRequiresForce(t *testing.T) {
	configDir, keyringDir, envVars, cleanup := setupTestEnv(t)
	defer cleanup()

	writeConfig(t, configDir, `
[profiles]
  [profiles.example]
    email = "old@example.com"
    auth_type = "api_key"
`)
	writeKeyringItem(t, keyringDir, "example-"+authTypeAPIKey, []byte(testAPIKey))

	result := runCfVaultWithStdin(t, envVars, strings.NewReader(testAPIToken), "add", "example", "--"+flagAuthValueStdin)

	if result.ExitCode == 0 {
		t.Fatalf("expected non-zero exit without --force, got 0\nstdout: %s\nstderr: %s", result.Stdout, result.Stderr)
	}
	if !strings.Contains(result.Stderr, "already exists") || !strings.Contains(result.Stderr, "--"+flagForce) {
		t.Errorf("expected existing profile error mentioning --force, got stderr=%q", result.Stderr)
	}
	if got := readTestConfig(t, configDir).Profiles["example"]; got.Email != "old@example.com" || got.AuthType != authTypeAPIKey {
		t.Errorf("expected existing profile to be untouched, got %+v", got)
	}
	if _, ok := readKeyringItem(t, keyringDir, "example-"+authTypeAPIToken); ok {
		t.Error("expected no credential to be stored without --force")
	}
	if _, ok := readKeyringItem(t, keyringDir, "example-"+authTypeAPIKey); !ok {
		t.Error("expected the existing credential to be kept without --force")
	}

	result = runCfVaultWithStdin(t, envVars, strings.NewReader(testAPIToken), "add", "example", "--"+flagAuthValueStdin, "--"+flagForce)

	if result.ExitCode != 0 {
		t.Fatalf("expected exit 0 with --force, got %d\nstderr: %s", result.ExitCode, result.Stderr)
	}
	if got := readTestConfig(t, configDir).Profiles["example"]; got.Email != "" || got.AuthType != authTypeAPIToken {
		t.Errorf("expected profile to be replaced, got %+v", got)
	}
	if stored, _ := readKeyringItem(t, keyringDir, "example-"+authTypeAPIToken); string(stored) != testAPIToken {
		t.Errorf("stored secret = %q, want %q", stored, testAPIToken)
	}
	// The replaced profile's credential lived under a different key, so it
	// would be orphaned in the keyring if it weren't removed.
	if _, ok := readKeyringItem(t, keyringDir, "example-"+authTypeAPIKey); ok {
		t.Error("expected the replaced profile's credential to be removed")
	}
}

func TestIntegration_Add_UnparseableConfigLeftUntouched(t *testing.T) {
	configDir, keyringDir, envVars, cleanup := setupTestEnv(t)
	defer cleanup()

	const corrupt = "[profiles.existing\nemail = \"user@example.com\"\n"
	writeConfig(t, configDir, corrupt)

	result := runCfVaultWithStdin(t, envVars, strings.NewReader(testAPIToken), "add", "example", "--"+flagAuthValueStdin)

	if result.ExitCode == 0 {
		t.Fatalf("expected non-zero exit, got 0\nstdout: %s\nstderr: %s", result.Stdout, result.Stderr)
	}
	if !strings.Contains(result.Stderr, "failed to parse the configuration file") {
		t.Errorf("expected config parse error, got stderr=%q", result.Stderr)
	}
	data, err := os.ReadFile(filepath.Join(configDir, configFileName))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != corrupt {
		t.Errorf("expected config to be left untouched, got %q", data)
	}
	if _, ok := readKeyringItem(t, keyringDir, "example-"+authTypeAPIToken); ok {
		t.Error("expected no credential to be stored")
	}
}

func TestIntegration_Add_UnknownTemplateRejectedBeforeCredentials(t *testing.T) {
	_, _, envVars, cleanup := setupTestEnv(t)
	defer cleanup()

	// No credential source is given, so reaching the credential step would
	// fail with a different error; the template error proves it ran first.
	result := runCfVault(t, envVars, "add", "example", "--"+flagProfileTemplate, "read-everything", "--"+flagSessionDuration, "15m")

	if result.ExitCode == 0 {
		t.Fatalf("expected non-zero exit, got 0\nstdout: %s\nstderr: %s", result.Stdout, result.Stderr)
	}
	if !strings.Contains(result.Stderr, "unable to generate policy for") || !strings.Contains(result.Stderr, "read-everything") {
		t.Errorf("expected unknown template error, got stderr=%q", result.Stderr)
	}
}

func TestIntegration_Add_InvalidSessionDurationRejectedBeforeCredentials(t *testing.T) {
	for _, duration := range []string{"banana", "0s", "-5m", "9s"} {
		t.Run(duration, func(t *testing.T) {
			configDir, _, envVars, cleanup := setupTestEnv(t)
			defer cleanup()

			// As above, no credential source proves the check ran first.
			result := runCfVault(t, envVars, "add", "example", "--"+flagProfileTemplate, policyTemplateReadOnly, "--"+flagSessionDuration, duration)

			if result.ExitCode == 0 {
				t.Fatalf("expected non-zero exit, got 0\nstdout: %s\nstderr: %s", result.Stdout, result.Stderr)
			}
			if !strings.Contains(result.Stderr, "--"+flagSessionDuration) || !strings.Contains(result.Stderr, duration) {
				t.Errorf("expected invalid session duration error, got stderr=%q", result.Stderr)
			}
			if _, err := os.Stat(filepath.Join(configDir, configFileName)); !os.IsNotExist(err) {
				t.Errorf("expected no config to be written, stat err = %v", err)
			}
		})
	}
}

// A template's policies are only ever used to create short lived tokens, and
// a session duration without policies has nothing to create a token with.
func TestIntegration_Add_TemplateAndSessionDurationRequireEachOther(t *testing.T) {
	tests := map[string][]string{
		"template alone":         {"--" + flagProfileTemplate, policyTemplateReadOnly},
		"session duration alone": {"--" + flagSessionDuration, "15m"},
	}
	for name, flags := range tests {
		t.Run(name, func(t *testing.T) {
			_, _, envVars, cleanup := setupTestEnv(t)
			defer cleanup()

			result := runCfVault(t, envVars, append([]string{"add", "example"}, flags...)...)

			if result.ExitCode == 0 {
				t.Fatalf("expected non-zero exit, got 0\nstdout: %s\nstderr: %s", result.Stdout, result.Stderr)
			}
			for _, flag := range []string{flagProfileTemplate, flagSessionDuration} {
				if !strings.Contains(result.Stderr, flag) {
					t.Errorf("expected error naming %s, got stderr=%q", flag, result.Stderr)
				}
			}
		})
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

	_, err := generatePolicy(context.Background(), client, "read-only", "user-000", nil, nil)
	if err == nil {
		t.Fatal("expected error for empty zone bucket, got nil")
	}
	if !strings.Contains(err.Error(), "empty") || !strings.Contains(err.Error(), "zone=0") {
		t.Errorf("error should mention empty bucket and zone=0, got: %v", err)
	}
}

// The account bucket only matters when an account policy is emitted. A
// zone-only restriction drops that policy, so a missing account bucket must
// not block it — but it still must when accounts are in play.
func TestGeneratePolicy_EmptyAccountBucket(t *testing.T) {
	const acct = "01a7362d577a6c3019a474fd6f485823"
	const zone = "023e105f4ecef8ad9ca31a8372d0c353"
	groups := []mockPermGroup{
		{ID: "zone-read", Name: "DNS Read", Scopes: []string{"com.cloudflare.api.account.zone"}},
		{ID: "user-read", Name: "Memberships Read", Scopes: []string{"com.cloudflare.api.user"}},
	}
	srv := newMockPermGroupServer(t, groups)
	client := newTestClient(t, srv.URL)

	policies, err := generatePolicy(context.Background(), client, "read-only", "user-000", nil, []string{zone})
	if err != nil {
		t.Fatalf("zone-only restriction should not need account groups, got: %v", err)
	}
	if len(policies) != 2 {
		t.Fatalf("expected zone and user policies, got %d", len(policies))
	}

	cases := map[string]struct{ accountIDs, zoneIDs []string }{
		"unrestricted":        {nil, nil},
		"account restricted":  {[]string{acct}, nil},
		"account and zone ID": {[]string{acct}, []string{zone}},
	}
	for name, c := range cases {
		_, err := generatePolicy(context.Background(), client, "read-only", "user-000", c.accountIDs, c.zoneIDs)
		if err == nil || !strings.Contains(err.Error(), "account=0") {
			t.Errorf("%s: expected empty account bucket error, got %v", name, err)
		}
	}
}

func TestGeneratePolicy_APIError(t *testing.T) {
	// Server returns 500 for any request.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	client := newTestClient(t, srv.URL)

	_, err := generatePolicy(context.Background(), client, "read-only", "user-err", nil, nil)
	if err == nil {
		t.Fatal("expected error for API 500 response, got nil")
	}
}

func TestParseSessionDuration_Minimum(t *testing.T) {
	if d, err := parseSessionDuration("10s"); err != nil || d != minSessionDuration {
		t.Errorf("10s: got (%s, %v), want it accepted", d, err)
	}
	if _, err := parseSessionDuration("9999ms"); err == nil {
		t.Error("9999ms: expected it to be rejected as shorter than the minimum")
	}
}
