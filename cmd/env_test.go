package cmd

import (
	"testing"
)

func TestEnviron_Set(t *testing.T) {
	e := environ{"FOO=bar"}
	e.Set("BAZ", "qux")
	found := false
	for _, s := range e {
		if s == "BAZ=qux" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected BAZ=qux in environ, got %v", []string(e))
	}
}

func TestEnviron_SetOverwrites(t *testing.T) {
	e := environ{"FOO=bar"}
	e.Set("FOO", "baz")
	for _, s := range e {
		if s == "FOO=bar" {
			t.Error("expected old FOO=bar to be replaced")
		}
	}
	found := false
	for _, s := range e {
		if s == "FOO=baz" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected FOO=baz in environ, got %v", []string(e))
	}
}

func TestEnviron_Unset(t *testing.T) {
	e := environ{"FOO=bar", "BAZ=qux"}
	e.Unset("FOO")
	for _, s := range e {
		if s == "FOO=bar" {
			t.Error("expected FOO=bar to be removed")
		}
	}
	if len(e) != 1 {
		t.Errorf("expected 1 entry, got %d: %v", len(e), []string(e))
	}
}

func TestEnviron_UnsetMissing(t *testing.T) {
	e := environ{"FOO=bar"}
	e.Unset("MISSING") // should not panic
	if len(e) != 1 {
		t.Errorf("expected 1 entry unchanged, got %d", len(e))
	}
}
