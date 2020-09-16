module github.com/jacobbednarz/cf-vault

go 1.15

require (
	cloud.google.com/go v0.65.0
	github.com/99designs/keyring v1.1.5
	github.com/BurntSushi/toml v0.3.1
	github.com/cosiner/argv v0.1.0 // indirect
	github.com/google/martian v2.1.0+incompatible
	github.com/google/pprof v0.0.0-20200905233945-acf8798be1f7 // indirect
	github.com/googleapis/gax-go v2.0.2+incompatible // indirect
	github.com/mitchellh/go-homedir v1.1.0
	github.com/sirupsen/logrus v1.2.0
	github.com/spf13/cobra v1.0.0
	github.com/spf13/viper v1.4.0
	golang.org/x/tools v0.0.0-20200915201639-f4cefd1cb5ba
	google.golang.org/api v0.32.0 // indirect
	gopkg.in/ini.v1 v1.61.0
)

replace github.com/keybase/go-keychain => github.com/99designs/go-keychain v0.0.0-20191008050251-8e49817e8af4
