package cmd

import (
	"slices"
	"strings"
)

// environ is a slice of strings representing the environment, in the form
// "key=value".
type environ []string

// Unset removes every entry for key
func (e *environ) Unset(key string) {
	prefix := key + "="
	*e = slices.DeleteFunc(*e, func(kv string) bool {
		return strings.HasPrefix(kv, prefix)
	})
}

// Set adds an environment variable, replacing any existing ones of the same key
func (e *environ) Set(key, val string) {
	e.Unset(key)
	*e = append(*e, key+"="+val)
}
