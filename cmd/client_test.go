package cmd

import "testing"

func TestNewClient_APIToken(t *testing.T) {
	c := newClient("test-token", "api_token", "")
	if c == nil {
		t.Fatal("expected non-nil client for api_token auth type")
	}
}

func TestNewClient_APIKey(t *testing.T) {
	c := newClient("test-key", "api_key", "user@example.com")
	if c == nil {
		t.Fatal("expected non-nil client for api_key auth type")
	}
}
