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

[![asciicast](https://asciinema.org/a/ukBkHKuITQRVAjEkKcRzz5Ryp.svg)](https://asciinema.org/a/ukBkHKuITQRVAjEkKcRzz5Ryp)

## Usage

`cf-vault` allows you to manage your Cloudflare credentials in a safe place and
only expose the credentials to the processes that require them and only for a
limited timespan.

```shell
$ env | grep -i cloudflare
# => no results

$ cf-vault exec work -- env | grep -i cloudflare
CLOUDFLARE_EMAIL=jacob@example.com
CLOUDFLARE_API_KEY=s3cr3t
```
