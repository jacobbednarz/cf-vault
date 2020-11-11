module github.com/jacobbednarz/cf-vault

go 1.15

require (
	github.com/99designs/keyring v1.1.6
	github.com/mitchellh/go-homedir v1.1.0
	github.com/pelletier/go-toml v1.8.2-0.20201011232708-5b4e7e5dcc56
	github.com/sirupsen/logrus v1.2.0
	github.com/spf13/cobra v1.0.0
	github.com/stretchr/testify v1.4.0 // indirect
	golang.org/x/crypto v0.0.0-20200622213623-75b288015ac9
	golang.org/x/sys v0.0.0-20200905004654-be1d3432aa8f // indirect
)

replace github.com/keybase/go-keychain => github.com/99designs/go-keychain v0.0.0-20191008050251-8e49817e8af4
