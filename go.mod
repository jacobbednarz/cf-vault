module github.com/jacobbednarz/cf-vault

go 1.15

require (
	github.com/99designs/keyring v1.1.6
	github.com/cloudflare/cloudflare-go v0.42.0
	github.com/kr/pretty v0.2.0 // indirect
	github.com/mitchellh/go-homedir v1.1.0
	github.com/olekukonko/tablewriter v0.0.5
	github.com/pelletier/go-toml v1.9.5
	github.com/sirupsen/logrus v1.8.1
	github.com/spf13/cobra v1.5.0
	golang.org/x/crypto v0.0.0-20210817164053-32db794688a5
	gopkg.in/check.v1 v1.0.0-20190902080502-41f04d3bba15 // indirect
)

replace github.com/keybase/go-keychain => github.com/99designs/go-keychain v0.0.0-20191008050251-8e49817e8af4
