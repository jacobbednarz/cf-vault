module github.com/jacobbednarz/cf-vault

go 1.15

require (
	github.com/99designs/keyring v1.1.6
	github.com/cloudflare/cloudflare-go v0.29.0
	github.com/mitchellh/go-homedir v1.1.0
	github.com/olekukonko/tablewriter v0.0.5
	github.com/pelletier/go-toml v1.9.4
	github.com/sirupsen/logrus v1.8.1
	github.com/spf13/cobra v1.3.0
	golang.org/x/crypto v0.0.0-20210817164053-32db794688a5
)

replace github.com/keybase/go-keychain => github.com/99designs/go-keychain v0.0.0-20191008050251-8e49817e8af4
