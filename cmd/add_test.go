package cmd

import "testing"

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
	}
}
