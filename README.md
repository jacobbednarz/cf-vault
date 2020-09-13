# cf-vault

Manage your Cloudflare credentials, securely.

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
