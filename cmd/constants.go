package cmd

const (
	// Names of files and directories cf-vault owns on disk. These form part of
	// the on-disk contract, so changing any of them orphans existing installs.
	configFileName             = "config.toml"
	keyringDirName             = "keys"
	secretsDirName             = "secrets"
	ageSecretFileExt           = ".age"
	ageIdentitySEFileName      = "identity-se.txt"
	ageIdentityYubikeyFileName = "identity-yubikey.txt"
	yubikeyIdentityMarker      = "AGE-PLUGIN-YUBIKEY-"

	// Environment variables read by cf-vault.
	envVaultSession   = "CLOUDFLARE_VAULT_SESSION"
	envFilePassphrase = "CF_VAULT_FILE_PASSPHRASE"
	envKeyringBackend = "CF_VAULT_BACKEND"
	envXDGConfigHome  = "XDG_CONFIG_HOME"
	envXDGDataHome    = "XDG_DATA_HOME"
	envShell          = "SHELL"

	// Environment variables populated for commands run via `exec`. Both the
	// `CLOUDFLARE_` and legacy `CF_` prefixes are set so older tooling keeps
	// working.
	envPrefixCloudflare        = "CLOUDFLARE_"
	envPrefixCF                = "CF_"
	envCloudflareEmail         = envPrefixCloudflare + "EMAIL"
	envCFEmail                 = envPrefixCF + "EMAIL"
	envCloudflareAPIToken      = envPrefixCloudflare + "API_TOKEN"
	envCFAPIToken              = envPrefixCF + "API_TOKEN"
	envCloudflareSessionExpiry = envPrefixCloudflare + "SESSION_EXPIRY"

	// Authentication types persisted to `auth_type` in the config file.
	authTypeAPIKey   = "api_key"
	authTypeAPIToken = "api_token"

	// Predefined policy templates accepted by `--profile-template`.
	policyTemplateReadOnly        = "read-only"
	policyTemplateWriteEverything = "write-everything"

	// Cloudflare API token policy values.
	policyEffectAllow         = "allow"
	policyResourceAllAccounts = "com.cloudflare.api.account.*"
	policyResourceAllZones    = "com.cloudflare.api.account.zone.*"
	policyResourceUserPrefix  = "com.cloudflare.api.user."

	// Command line flag names shared between flag registration and lookup.
	flagVerbose         = "verbose"
	flagProfileTemplate = "profile-template"
	flagSessionDuration = "session-duration"
	flagSecureEnclave   = "secure-enclave"
	flagYubikey         = "yubikey"

	// External binaries cf-vault shells out to for age-based secret backends.
	binAge              = "age"
	binAgePluginSE      = "age-plugin-se"
	binAgePluginYubikey = "age-plugin-yubikey"

	// User facing, non-error output.
	promptEmailAddress        = "Email address: "
	promptAuthValue           = "Authentication value (API key or API token): "
	msgSuccessKeyring         = "\nSuccess! Credentials have been set and are now ready for use!"
	msgSuccessSecureEnclave   = "\nSuccess! Credentials encrypted to the Secure Enclave and are now ready for use!"
	msgSuccessYubikey         = "\nSuccess! Credentials encrypted to a YubiKey identity and are now ready for use!"
	msgFmtNoProfilesFound     = "no profiles found at %s\n"
	msgFmtLegacyConfigWarning = "Warning: XDG directories are configured but legacy data exists at %s. " +
		"Consider migrating your config and keys to the new XDG-compliant locations.\n"
	msgFmtPreexistingCredentials = "%s already set in the calling shell. Any of these referenced in " +
		"the command's arguments were expanded by that shell before cf-vault ran and carry the stale " +
		"values. Unset them, or wrap the command in `sh -c '...'` so the profile's values are used."
)
