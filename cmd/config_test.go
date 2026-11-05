package cmd

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/cloudflare/cloudflare-go/v7"
	"github.com/cloudflare/cloudflare-go/v7/shared"
)

var savedConfig = tomlConfig{Profiles: map[string]profile{
	"work": {AuthType: authTypeAPIToken},
}}

func TestProfilePrepare(t *testing.T) {
	wantPolicies := []shared.TokenPolicyParam{{
		Effect: cloudflare.F(shared.TokenPolicyEffectAllow),
		PermissionGroups: cloudflare.F([]shared.TokenPolicyPermissionGroupParam{{
			ID: cloudflare.F("zone-read"),
		}}),
		Resources: cloudflare.F[shared.TokenPolicyResourcesUnionParam](shared.TokenPolicyResourcesIAMResourcesTypeObjectStringParam{
			policyResourceAllZones: "*",
		}),
	}}
	tests := map[string]struct {
		profile  profile
		duration time.Duration
		policies []shared.TokenPolicyParam
	}{
		"long_lived_key": {profile: profile{AuthType: authTypeAPIKey}},
		"long_lived_token_ignores_unused_policies": {
			profile: profile{AuthType: authTypeAPIToken, Policies: []policy{{Effect: "unused"}}},
		},
		"short_lived_token": {
			profile: profile{
				AuthType:        authTypeAPIToken,
				SessionDuration: "15m500ms",
				Policies: []policy{{
					Effect:           policyEffectAllow,
					PermissionGroups: []permissionGroup{{ID: "zone-read", Name: "Zone Read"}},
					Resources:        map[string]interface{}{policyResourceAllZones: "*"},
				}},
			},
			duration: 15*time.Minute + 500*time.Millisecond,
			policies: wantPolicies,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			duration, policies, err := tt.profile.prepare()
			if err != nil {
				t.Fatal(err)
			}
			if duration != tt.duration || !reflect.DeepEqual(policies, tt.policies) {
				t.Errorf("got (%s, %#v), want (%s, %#v)", duration, policies, tt.duration, tt.policies)
			}
		})
	}
}

func TestSaveConfig_OnlyOwnerCanRead(t *testing.T) {
	for name, existing := range map[string]bool{"new file": false, "replacing a 0700 file": true} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "cf-vault", configFileName)
			if existing {
				if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, nil, 0o700); err != nil {
					t.Fatal(err)
				}
			}

			if err := saveConfig(path, savedConfig); err != nil {
				t.Fatal(err)
			}

			info, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if mode := info.Mode().Perm(); mode != 0o600 {
				t.Errorf("config mode = %o, want 600", mode)
			}
			if got, err := loadConfig(path); err != nil || got.Profiles["work"].AuthType != authTypeAPIToken {
				t.Errorf("loadConfig after save = %+v, %v", got, err)
			}
		})
	}
}

// A write that fails part way must leave the previous config in place, not a
// truncated file that has lost every profile.
func TestSaveConfig_FailedWriteKeepsPreviousConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, configFileName)
	const previous = "[profiles.work]\nauth_type = \"api_token\"\n"
	if err := os.WriteFile(path, []byte(previous), 0o600); err != nil {
		t.Fatal(err)
	}

	unencodable := tomlConfig{Profiles: map[string]profile{
		"broken": {Policies: []policy{{Resources: map[string]interface{}{"x": make(chan int)}}}},
	}}
	if err := saveConfig(path, unencodable); err == nil {
		t.Fatal("expected encoding to fail")
	}

	if data, _ := os.ReadFile(path); string(data) != previous {
		t.Errorf("config after failed save = %q, want it untouched", data)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Errorf("expected only the config file to remain, got %v", entries)
	}
}

// Replacing the file by renaming over it must not swap a symlinked config,
// such as one managed from a dotfiles repository, for a regular file.
func TestSaveConfig_WritesThroughSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "dotfiles", configFileName)
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, configFileName)
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	if err := saveConfig(link, savedConfig); err != nil {
		t.Fatal(err)
	}

	if info, err := os.Lstat(link); err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("expected %s to remain a symlink, got %v, %v", link, info, err)
	}
	if got, err := loadConfig(target); err != nil || got.Profiles["work"].AuthType != authTypeAPIToken {
		t.Errorf("symlink target after save = %+v, %v", got, err)
	}
}

// A config linked from a dotfiles repository before the target exists must
// still be written through the link, creating the target, as a first `add`
// would otherwise quietly replace the link with a regular file.
func TestSaveConfig_WritesThroughDanglingSymlink(t *testing.T) {
	for name, relative := range map[string]bool{"absolute link": false, "relative link": true} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			target := filepath.Join(dir, "dotfiles", "cf-vault", configFileName)
			link := filepath.Join(dir, "config", configFileName)
			if err := os.MkdirAll(filepath.Dir(link), 0o700); err != nil {
				t.Fatal(err)
			}
			linkTo := target
			if relative {
				linkTo = filepath.Join("..", "dotfiles", "cf-vault", configFileName)
			}
			if err := os.Symlink(linkTo, link); err != nil {
				t.Fatal(err)
			}

			if err := saveConfig(link, savedConfig); err != nil {
				t.Fatal(err)
			}

			if info, err := os.Lstat(link); err != nil || info.Mode()&os.ModeSymlink == 0 {
				t.Fatalf("expected %s to remain a symlink, got %v, %v", link, info, err)
			}
			if got, err := loadConfig(target); err != nil || got.Profiles["work"].AuthType != authTypeAPIToken {
				t.Errorf("symlink target after save = %+v, %v", got, err)
			}
		})
	}
}
