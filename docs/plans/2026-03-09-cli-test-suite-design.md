# CLI Test Suite Design

**Date:** 2026-03-09
**Branch:** fresh-cli-testing

## Goal

Add automated CLI interaction tests covering all commands (`version`, `list`, `exec`, `add`) so that manual testing is no longer required for basic coverage.

## Architecture

### In-process command tests (primary)

Build on the existing `paths_test.go` pattern. Each test:
- Creates a temp config dir and temp keyring dir
- Sets `XDG_CONFIG_HOME` / `XDG_DATA_HOME` env vars to point at temp dirs
- Writes a minimal `config.toml` fixture where needed
- Redirects stdout/stderr to `bytes.Buffer` via cobra's `SetOut`/`SetErr`
- Calls the cobra command directly (no subprocess)
- Asserts on output content and exit behaviour

A `cmd/testing_helpers_test.go` file centralises the setup/teardown helpers shared across test files.

### Subprocess smoke tests (secondary)

A `cmd/integration_test.go` uses `TestMain` to compile the binary once into a temp dir, then runs it as a subprocess for a handful of end-to-end smoke tests. Skipped automatically if `go build` fails (e.g. missing env in CI without full toolchain).

## Test Coverage Plan

### `version` command
- Output matches expected format: `cf-vault <version> (<go>, <compiler>-<arch>)`
- Exit code 0

### `list` command
- Empty config → helpful "no profiles" message (or empty output, verify current behaviour)
- Config with one API-key profile → profile name + auth type appear in output
- Config with one API-token profile → correct auth type shown
- Multiple profiles → all appear

### `exec` command
- Missing profile → non-zero exit + error message
- Profile exists, API key stored → env vars injected correctly (`CLOUDFLARE_EMAIL`, `CLOUDFLARE_API_KEY`, etc.)
- Profile exists, API token stored → token env vars injected
- `--` passthrough command receives correct env

### `add` command (non-interactive paths only)
- Invalid/missing args → non-zero exit + usage hint
- `--profile-template` flag with invalid value → error message
- Auto auth-type detection logic tested at unit level (regex helpers)

## Keyring Strategy

Tests use the `file` keyring backend (supported by `99designs/keyring`) pointed at a temp directory. This avoids any OS keyring dependency and works in CI without special permissions.

## File Layout

```
cmd/
  paths_test.go              # existing
  testing_helpers_test.go    # NEW: shared test setup helpers
  version_test.go            # NEW: version command tests
  list_test.go               # NEW: list command tests
  exec_test.go               # NEW: exec command tests
  add_test.go                # NEW: add command unit tests
  integration_test.go        # NEW: subprocess smoke tests (TestMain builds binary)
```

## Non-Goals

- Testing interactive `add` prompts (requires terminal emulation, out of scope)
- Live Cloudflare API calls (no network in tests)
- Testing OS-native keyring backends (macOS Keychain etc.)
