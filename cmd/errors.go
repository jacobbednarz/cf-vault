package cmd

import "errors"

// Sentinel errors for failures that carry no dynamic context.
var (
	errProfileArgRequired       = errors.New("requires a profile argument")
	errProfileNameEmpty         = errors.New("profile name must not be empty")
	errInvalidAuthValueFormat   = errors.New("invalid API token or API key format")
	errNestedSession            = errors.New("cf-vault sessions shouldn't be nested, unset CLOUDFLARE_VAULT_SESSION to continue or open a new shell session")
	errAgeNotFound              = errors.New("age not found on PATH; install it (`brew install age`)")
	errYubikeyIdentityNotFound  = errors.New("no YubiKey identity found; run `age-plugin-yubikey --generate` to enroll one, then re-run this command")
	errYubikeyRecipientNotFound = errors.New("could not extract age1yubikey1… recipient from `age-plugin-yubikey --identity` output")
)

// Error message strings. Most are format strings that interpolate context or
// wrap a cause.
const (
	// errMsgUserFetchForPolicy is logged rather than returned; it is a full
	// sentence aimed at the user, so it doesn't follow Go's error string style.
	errMsgUserFetchForPolicy = "failed to fetch user ID from the Cloudflare API which is required to generate the predefined short lived token policies. If you are using API tokens, please allow the permission to access your user details and try again."

	// Profiles and configuration.
	errFmtInvalidProfileName    = "profile name %q is invalid; use only letters, digits, `.`, `_`, `-`, and do not start with `.`"
	errFmtProfileNotFound       = "no profile matching %q found in the configuration file at %s"
	errFmtUnknownSecretBackend  = "profile %q has unknown secret_backend %q; valid values are %q, %q, or unset for keychain"
	errFmtHomeDirNotFound       = "unable to find home directory: %w"
	errFmtOpenConfigFile        = "failed to open file at %s"
	errFmtReadAuthValue         = "unable to read authentication value: %s"
	errFmtDetectAuthType        = "failed to detect authentication type: %s"
	errFmtExecutableNotFound    = "couldn't find the executable '%s': %s"
	errFmtCreateAPIToken        = "failed to create API token: %s"
	errFmtFetchPermissionGroups = "failed to fetch permission groups: %w"
	errFmtUnknownPolicyTemplate = "unable to generate policy for %q, valid policy names: [" + policyTemplateReadOnly + ", " + policyTemplateWriteEverything + "]"
	errFmtEmptyPolicyBucket     = "one or more policy buckets is empty for policy type %q (account=%d, zone=%d, user=%d); check API permissions"

	// Keyring backend.
	errFmtOpenKeyring    = "failed to open keyring backend: %s"
	errFmtGetKeyringItem = "failed to get item from keyring: %s"
	errFmtAddKeyringItem = "Error adding credentials to keyring: %s"

	// age and its plugins.
	errFmtUnknownAgeBackend        = "unknown age backend %q"
	errFmtDecryptAgeBackend        = "failed to decrypt secret (%s): %s"
	errFmtAgePluginSENotFound      = "age-plugin-se not found on PATH; install it (`brew install age-plugin-se`) or place an existing identity file at %s"
	errFmtAgePluginSEKeygen        = "age-plugin-se keygen failed: %w"
	errFmtAgePluginYubikeyNotFound = "age-plugin-yubikey not found on PATH; install it (`brew install age-plugin-yubikey`) and either run `age-plugin-yubikey --generate` to enroll a new key, or place an existing identity file at %s"
	errFmtYubikeyIdentityCommand   = "`age-plugin-yubikey --identity` failed (is a YubiKey plugged in?); if this is a fresh key, run `age-plugin-yubikey --generate` first: %w\n%s"
	errFmtMultipleYubikeyIdentity  = "multiple YubiKey identities detected — pick one and save its identity block to %s"
	errFmtCacheYubikeyIdentity     = "failed to cache YubiKey identity at %s: %w"
	errFmtEmptyAgeRecipient        = "empty recipient on `# %s` line in %s"
	errFmtAgeRecipientNotFound     = "no `# public key:` or `# recipient:` line found in %s"
	errFmtAgeEncrypt               = "age encryption failed: %w"
	errFmtAgeDecrypt               = "age decryption failed: %w"
	errFmtAgeCiphertextMissing     = "secret ciphertext missing at %s: %w"
)
