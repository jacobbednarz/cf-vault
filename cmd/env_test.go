package cmd

import (
	"slices"
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
	if len(e) != 1 {
		t.Errorf("expected 1 entry after overwrite, got %d: %v", len(e), []string(e))
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

// An environment can carry the same key more than once, and a child process
// may read any of the copies, so every one must go.
func TestEnviron_UnsetDuplicates(t *testing.T) {
	e := environ{"FOO=stale", "BAR=keep", "FOO=staler", "FOOBAR=keep"}
	e.Unset("FOO")
	if want := (environ{"BAR=keep", "FOOBAR=keep"}); !slices.Equal(e, want) {
		t.Errorf("got %v, want %v", []string(e), []string(want))
	}
}
