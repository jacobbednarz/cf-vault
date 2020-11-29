# cf-vault

Manage your Cloudflare credentials, securely.

The goal of this project is to ensure that when you need to interact with Cloudflare:

- You're not storing credentials unencrypted; and
- You're not exposing your credentials to the entire environment or to all
  processes; and
- Your not using long lived credentials

To achieve this, `cf-vault` uses the concept of profiles with associated scopes
to either generate short lived API tokens or retrieve the API key from secure
storage (such as Mac OS keychain).

## Demo

![demo](https://user-images.githubusercontent.com/283234/94203859-8c2d8680-ff03-11ea-8cd6-21161224c2ff.gif)


## Install

```
$ brew tap jacobbednarz/cf-vault
$ brew cask install jacobbednarz/cf-vault/cf-vault
```

## Getting started

1. First step is to generate a new API key or API token. Either will work
   however there are some subtle differences to take into consideration before
   choosing your path.

   - API tokens **are not** supported by all services yet. Regardless of whether
     you are using the short lived credentials or long lived token, it may not
     work for all services and you may need to have a backup profile defined
     using an API key to cover all scenarios .
   - API keys **are** supported everywhere however they cannot be scoped. API
     keys have the permission and scopes that your user account has. This can be
     dangerous so be sure to tread carefully as it may have unintended consequences.

   While it is possible (and better practice of [principle of least privilege]),
   to use an API token with only permissions to create a new API token, this
   isn't really viable for all use cases yet. The recommended approach is to use
   the API key for the profile and rely on a custom policy to scope the short
   lived credential. This allows the best of both worlds where if you need to
   use a service that doesn't support API tokens, you don't need to create a new
   profile.

   To create a new API token:

   ```
   > https://dash.cloudflare.com/
     > My Profile
       > API Tokens
         > Create API token
   ```

   To retrieve your API key:

    ```
    > https://dash.cloudflare.com/
      > My Profile
        > API Tokens
          > Global API Key
    ```

1. If you're using an API key, you can skip to the next step. Otherwise,
   navigate through the UI and configure what permissions and resources you'd
   like to assign to the token. If you're looking to use an API token to
   generate short lived API tokens, you should only need the single predefined
   "Create API tokens" permission. See the section below on generating the desired
   TOML output for instructions on how to do automatically convert policies from
   API responses.

   Note: Be sure to note down the API token **before** closing/navigating away
   from the UI as you won't be able to retrieve it again.

1. Once you have your API key or API token value, you can start using `cf-vault`
   by creating a profile. A profile is the collection of configuration that
   tells `cf-vault` how you intend to interact with the Cloudflare credentials.
   You need to start by calling `cf-vault add
   [your-profile-name]` where `[your-profile-name]` is a label for what the
   credential/use of the profile is. Some examples:

   - `cf-vault add write-everything`
   - `cf-vault add read-only`
   - `cf-vault add super-scary-access-everything`
   - `cf-vault add api-token-to-create-other-tokens`

   There is no limit on how many profiles you have if you prefer to have
   specific profiles for your use cases.

1. Now that you have created a profile, you can use it with `cf-vault exec
   [your-profile-name]`.

If you do not wish to use the short lived credentials functionality,
that's totally fine and you can do so by omitting the `session_duration` value
and instead the long lived credentials you've setup will be used.

## Usage

`cf-vault` allows you to manage your Cloudflare credentials in a safe place and
only expose the credentials to the processes that require them and only for a
limited timespan.

```shell
$ env | grep -i cloudflare
# => no results

$ cf-vault exec work -- env | grep -i cloudflare
CLOUDFLARE_VAULT_SESSION=work
CLOUDFLARE_EMAIL=jacob@example.com
CLOUDFLARE_API_KEY=s3cr3t
```

If you don't provide a command, you will be dropped into a new shell with the
credentials populated.

```shell
$ cf-vault exec work
$ env | grep -i cloudflare
CLOUDFLARE_VAULT_SESSION=work
CLOUDFLARE_EMAIL=jacob@example.com
CLOUDFLARE_API_KEY=s3cr3t

$ exit
$ env | grep -i cloudflare
# => no results
```

## Predefined short lived token policies

If you don't need to generate a custom token policy, you can instead use one of
the predefined templates which takes care of the heavy lifting for you. You can
use `read-only` (read all resources) or `write-everything` (write all resources)
as the `--profile-template` flag and it will generate everything needed behind
the scenes on your behalf. Note: You **still** need to provide
`--session-duration` as well otherwise the short lived tokens will not be
generated.

Examples:

- `cf-vault add my-read-profile-name --profile-template "read-only" --session-duration "15m"`
- `cf-vault add my-write-profile-name --profile-template "write-everything" --session-duration "15m"`

## Generating token policies

While TOML is more readable, its not always straight forward to generate the
desired output. Instead, you can use the Cloudflare dashboard to build the
policy you'd like and then covert that to TOML using some tooling to avoid
manually building your policy (though you can if you understand the syntax!).

1. Using `cf-vault add` create your profile following the prompts.
1. Create the token you'd like to use on the command line using the Cloudflare
   dashboard.
1. Make the API call to fetch the token you've just created. See
   https://api.cloudflare.com/#user-api-tokens-token-details or
   https://api.cloudflare.com/#user-api-tokens-list-tokens to fetch all tokens.
1. Write the contents of the single `result` JSON payload to a local file. For
   the example, I'll use `example_token.json` for the documentation.
1. Run the following command using `docker` which will pull the `go-toml` tool
   for coverting JSON -> TOML. Remember to replace `example_token.json` with
   your filename.

   ```
   docker run -v $PWD:/workdir pelletier/go-toml jsontoml /workdir/example_token.json
   ```

1. Paste the generated `policy` into your configuration file. You will need to
   adjust the structure slightly to match the hierarchy. For instance, if I have
  the following profile:

  ```toml
  [profiles]

  [profiles.doco-example]
    auth_type = "api_token"
    email = "me@example.com"
    session_duration = "15m"
  ```

  and my policy output:

  ```toml
  [[policies]]
  effect = "allow"

  [[policies.permission_groups]]
    id = "eb258a38ea634c86a0c89da6b27cb6b6"
    name = "Access: Apps and Policies Read"

  [[policies.permission_groups]]
    id = "517b21aee92c4d89936c976ba6e4be55"
    name = "Zone Settings Read"

  [[policies.permission_groups]]
    id = "c8fed203ed3043cba015a93ad1616f1f"
    name = "Zone Read"

  # .. snip
  ```

  The policy needs to be updated to prepend `profiles.doco-example` to the
  section keys.

  ```toml
  [[profiles.doco-example.policies]]
  effect = "allow"

  [[profiles.doco-example.policies.permission_groups]]
    id = "eb258a38ea634c86a0c89da6b27cb6b6"
    name = "Access: Apps and Policies Read"

  [[profiles.doco-example.policies.permission_groups]]
    id = "517b21aee92c4d89936c976ba6e4be55"
    name = "Zone Settings Read"

  [[profiles.doco-example.policies.permission_groups]]
    id = "c8fed203ed3043cba015a93ad1616f1f"
    name = "Zone Read"

  # .. snip
  ```

  Making the complete configuration look like:

```toml
  [profiles]

  [profiles.doco-example]
    auth_type = "api_token"
    email = "me@example.com"
    session_duration = "15m"

    [[policies]]
    effect = "allow"

    [[policies.permission_groups]]
      id = "eb258a38ea634c86a0c89da6b27cb6b6"
      name = "Access: Apps and Policies Read"

    [[policies.permission_groups]]
      id = "517b21aee92c4d89936c976ba6e4be55"
      name = "Zone Settings Read"

    [[policies.permission_groups]]
      id = "c8fed203ed3043cba015a93ad1616f1f"
      name = "Zone Read"

    # .. snip
  ```

[principle of least privilege]: https://en.wikipedia.org/wiki/Principle_of_least_privilege
