package cmd

import (
	"strings"
	"testing"
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
