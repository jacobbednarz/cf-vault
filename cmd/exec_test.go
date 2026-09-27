package cmd

import (
	"bytes"
	"reflect"
	"strings"
	"testing"

	"github.com/cloudflare/cloudflare-go/v6/shared"
	"github.com/pelletier/go-toml"
)

// TestTokenPolicyResources_ConfigRoundTrip writes restricted template
// policies to TOML and reads them back the way `add` and `exec` do, proving
// nested account → zone resources survive the config file and reach the API
// as nested objects rather than stringified maps.
func TestTokenPolicyResources_ConfigRoundTrip(t *testing.T) {
	const acct = "01a7362d577a6c3019a474fd6f485823"
	const zone = "023e105f4ecef8ad9ca31a8372d0c353"

	written := tomlConfig{Profiles: map[string]profile{
		"restricted": {
			Email:    "me@example.com",
			AuthType: authTypeAPIToken,
			Policies: []policy{
				{Effect: policyEffectAllow, Resources: accountResources([]string{acct})},
				{Effect: policyEffectAllow, Resources: zoneResources([]string{acct}, nil)},
				{Effect: policyEffectAllow, Resources: zoneResources(nil, []string{zone})},
			},
		},
	}}

	var buf bytes.Buffer
	if err := toml.NewEncoder(&buf).Encode(written); err != nil {
		t.Fatalf("encode: %v", err)
	}
	var read tomlConfig
	if err := toml.Unmarshal(buf.Bytes(), &read); err != nil {
		t.Fatalf("decode: %v\n%s", err, buf.String())
	}

	want := []shared.TokenPolicyResourcesUnionParam{
		shared.TokenPolicyResourcesIAMResourcesTypeObjectStringParam{
			"com.cloudflare.api.account." + acct: "*",
		},
		shared.TokenPolicyResourcesIAMResourcesTypeObjectNestedParam{
			"com.cloudflare.api.account." + acct: {"com.cloudflare.api.account.zone.*": "*"},
		},
		shared.TokenPolicyResourcesIAMResourcesTypeObjectStringParam{
			"com.cloudflare.api.account.zone." + zone: "*",
		},
	}

	policies := read.Profiles["restricted"].Policies
	if len(policies) != len(want) {
		t.Fatalf("expected %d policies after round trip, got %d\n%s", len(want), len(policies), buf.String())
	}
	for i, p := range policies {
		got, err := tokenPolicyResources(p.Resources)
		if err != nil {
			t.Fatalf("policy[%d]: unexpected error: %v", i, err)
		}
		if !reflect.DeepEqual(got, want[i]) {
			t.Errorf("policy[%d]:\n got  %#v\n want %#v\nTOML:\n%s", i, got, want[i], buf.String())
		}
	}
}

func TestTokenPolicyResources_Rejects(t *testing.T) {
	tests := map[string]map[string]interface{}{
		"mixed flat and nested": {
			"com.cloudflare.api.account.zone.023e105f4ecef8ad9ca31a8372d0c353": "*",
			"com.cloudflare.api.account.01a7362d577a6c3019a474fd6f485823": map[string]interface{}{
				"com.cloudflare.api.account.zone.*": "*",
			},
		},
		"non-string value":        {"com.cloudflare.api.account.*": int64(1)},
		"non-string nested value": {"com.cloudflare.api.account.x": map[string]interface{}{"y": true}},
	}
	for name, resources := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := tokenPolicyResources(resources)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), "all strings or all tables of strings") {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}
