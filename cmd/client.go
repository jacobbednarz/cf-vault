package cmd

import (
	"github.com/cloudflare/cloudflare-go/v6"
	"github.com/cloudflare/cloudflare-go/v6/option"
)

// newClient constructs a cloudflare-go/v6 client from the stored auth credentials.
func newClient(authValue, authType, email string) *cloudflare.Client {
	// The SDK also authenticates with any credentials exported as CLOUDFLARE_*
	// variables. Clear them so a stale one in the calling shell isn't sent
	// alongside, or instead of, the profile's.
	opts := []option.RequestOption{
		option.WithHeaderDel("Authorization"),
		option.WithHeaderDel("X-Auth-Key"),
		option.WithHeaderDel("X-Auth-Email"),
		option.WithHeaderDel("X-Auth-User-Service-Key"),
	}
	if authType == authTypeAPIToken {
		return cloudflare.NewClient(append(opts, option.WithAPIToken(authValue))...)
	}
	return cloudflare.NewClient(append(opts,
		option.WithAPIKey(authValue),
		option.WithAPIEmail(email),
	)...)
}
