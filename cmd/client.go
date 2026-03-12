package cmd

import (
	"github.com/cloudflare/cloudflare-go/v6"
	"github.com/cloudflare/cloudflare-go/v6/option"
)

// newClient constructs a cloudflare-go/v6 client from the stored auth credentials.
func newClient(authValue, authType, email string) *cloudflare.Client {
	if authType == "api_token" {
		return cloudflare.NewClient(option.WithAPIToken(authValue))
	}
	return cloudflare.NewClient(
		option.WithAPIKey(authValue),
		option.WithAPIEmail(email),
	)
}
