package cmd

import (
	"context"
	"time"

	"github.com/cloudflare/cloudflare-go/v6"
	"github.com/cloudflare/cloudflare-go/v6/accounts"
	"github.com/cloudflare/cloudflare-go/v6/option"
	"github.com/cloudflare/cloudflare-go/v6/shared"
	"github.com/cloudflare/cloudflare-go/v6/user"
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

// The helpers below talk to the tokens API of whoever owns the credential: the
// user, or with a non-empty ownerAccountID, the account owning an account API
// token. Both APIs take and return the same shapes under different paths.

// listPermissionGroups returns the permission groups a token created by the
// credential's owner may be granted, keyed by the scope they apply to.
func listPermissionGroups(ctx context.Context, client *cloudflare.Client, ownerAccountID string) (map[string][]permissionGroup, error) {
	byScope := make(map[string][]permissionGroup)
	if ownerAccountID == "" {
		page, err := client.User.Tokens.PermissionGroups.List(ctx, user.TokenPermissionGroupListParams{})
		if err != nil {
			return nil, err
		}
		for _, g := range page.Result {
			addByScope(byScope, permissionGroup{ID: g.ID, Name: g.Name}, g.Scopes)
		}
		return byScope, nil
	}

	page, err := client.Accounts.Tokens.PermissionGroups.List(ctx, accounts.TokenPermissionGroupListParams{
		AccountID: cloudflare.F(ownerAccountID),
	})
	if err != nil {
		return nil, err
	}
	for _, g := range page.Result {
		addByScope(byScope, permissionGroup{ID: g.ID, Name: g.Name}, g.Scopes)
	}
	return byScope, nil
}

// addByScope files g under each of its scopes, whose type differs between the
// user and account APIs.
func addByScope[S ~string](byScope map[string][]permissionGroup, g permissionGroup, scopes []S) {
	for _, scope := range scopes {
		byScope[string(scope)] = append(byScope[string(scope)], g)
	}
}

// createToken creates an API token owned by the credential's owner and
// returns its value.
func createToken(ctx context.Context, client *cloudflare.Client, ownerAccountID, name string, expiresOn time.Time, policies []shared.TokenPolicyParam) (string, error) {
	if ownerAccountID == "" {
		token, err := client.User.Tokens.New(ctx, user.TokenNewParams{
			Name:      cloudflare.F(name),
			ExpiresOn: cloudflare.F(expiresOn),
			Policies:  cloudflare.F(policies),
		})
		if err != nil {
			return "", err
		}
		return token.Value, nil
	}

	token, err := client.Accounts.Tokens.New(ctx, accounts.TokenNewParams{
		AccountID: cloudflare.F(ownerAccountID),
		Name:      cloudflare.F(name),
		ExpiresOn: cloudflare.F(expiresOn),
		Policies:  cloudflare.F(policies),
	})
	if err != nil {
		return "", err
	}
	return token.Value, nil
}
