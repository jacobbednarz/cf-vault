module github.com/jacobbednarz/cf-vault

go 1.15

require (
	github.com/99designs/keyring v1.1.6
	github.com/cloudflare/cloudflare-go v0.27.0
	github.com/mitchellh/go-homedir v1.1.0
	github.com/olekukonko/tablewriter v0.0.5
	github.com/pelletier/go-toml v1.9.4
	github.com/sirupsen/logrus v1.8.1
	github.com/spf13/cobra v1.2.1
	golang.org/x/crypto v0.0.0-20200622213623-75b288015ac9
)

replace github.com/keybase/go-keychain => github.com/99designs/go-keychain v0.0.0-20191008050251-8e49817e8af4
