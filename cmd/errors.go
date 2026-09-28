package cmd

import "errors"

// Sentinel errors for failures that carry no dynamic context.
var (
	errProfileArgRequired           = errors.New("requires a profile argument")
	errProfileNameEmpty             = errors.New("profile name must not be empty")
	errInvalidAuthValueFormat       = errors.New("invalid API token or API key format")
	errNestedSession                = errors.New("cf-vault sessions shouldn't be nested, unset CLOUDFLARE_VAULT_SESSION to continue or open a new shell session")
	errAgeNotFound                  = errors.New("age not found on PATH; install it (`brew install age`)")
	errYubikeyIdentityNotFound      = errors.New("no YubiKey identity found; run `age-plugin-yubikey --generate` to enroll one, then re-run this command")
	errYubikeyRecipientNotFound     = errors.New("could not extract age1yubikey1… recipient from `age-plugin-yubikey --identity` output")
	errResourceIDsNeedTemplate      = errors.New("--" + flagAccountID + " and --" + flagZoneID + " can only be used with --" + flagProfileTemplate)
	errEmailRequiredForAPIKey       = errors.New("--" + flagEmail + " is required when adding a global API key")
	errAuthValueSourceRequired      = errors.New("stdin is not a terminal; pass --" + flagAuthValueStdin + " or set " + envAuthValue + " to provide the authentication value")
	errShellNotSet                  = errors.New("SHELL is not set, so there is no shell to start; pass the command to run after `--` instead")
	errEmptyShortLivedToken         = errors.New("the short lived token was created but Cloudflare returned no value for it")
	errNoPoliciesForSessionDuration = errors.New("session_duration is set but the profile has no policies to create a short lived token with; add policies or remove session_duration")
)

// Error format strings for failures that interpolate context or wrap a cause.
const (
	// Profiles and configuration.
	errFmtInvalidProfileName         = "profile name %q is invalid; use only letters, digits, `.`, `_`, `-`, and do not start with `.`"
	errFmtProfileNotFound            = "no profile matching %q found in the configuration file at %s"
	errFmtInvalidProfile             = "profile %q in %s is invalid: %w"
	errFmtProfileExists              = "profile %q already exists in %s; pass --" + flagForce + " to overwrite it"
	errFmtParseConfigFile            = "failed to parse the configuration file at %s: %w"
	errFmtInvalidSessionDuration     = "invalid session_duration: %w"
	errFmtInvalidSessionDurationFlag = "invalid --" + flagSessionDuration + ": %w"
	errFmtSessionDurationTooShort    = "%q is shorter than the minimum of %s"
	errFmtUnknownSecretBackend       = "profile %q has unknown secret_backend %q; valid values are %q, %q, or unset for keychain"
	errFmtHomeDirNotFound            = "unable to find home directory: %w"
	errFmtOpenConfigFile             = "failed to open file at %s: %w"
	errFmtReadAuthValue              = "unable to read authentication value: %w"
	errFmtDetectAuthType             = "failed to detect authentication type: %w"
	errFmtExecutableNotFound         = "couldn't find the executable '%s': %w"
	errFmtRunExecutable              = "failed to run %s: %w"
	errFmtCreateAPIToken             = "failed to create API token: %w"
	errFmtUserFetchForPolicy         = "failed to fetch the user ID the predefined token policies are scoped to; API tokens need permission to read user details: %w"
	errFmtFetchPermissionGroups      = "failed to fetch permission groups: %w"
	errFmtUnknownPolicyTemplate      = "unable to generate policy for %q, valid policy names: [" + policyTemplateReadOnly + ", " + policyTemplateWriteEverything + "]"
	errFmtEmptyPolicyBucket          = "one or more policy buckets is empty for policy type %q (account=%d, zone=%d, user=%d); check API permissions"
	errFmtInvalidResourceID          = "%s ID %q is invalid; expected a 32 character hexadecimal string"
	errFmtUnsupportedResources       = "policy resources must be either all strings or all tables of strings, got %v"

	// Keyring backend.
	errFmtOpenKeyring    = "failed to open keyring backend: %w"
	errFmtGetKeyringItem = "failed to get item from keyring: %w"
	errFmtAddKeyringItem = "failed to add credentials to keyring: %w"

	// age and its plugins.
	errFmtDecryptAgeBackend        = "failed to decrypt secret (%s): %w"
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
