package cmd

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"regexp"
	"strings"

	"github.com/cloudflare/cloudflare-go"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh/terminal"

	"github.com/99designs/keyring"
	"github.com/mitchellh/go-homedir"
	"github.com/spf13/cobra"

	"github.com/pelletier/go-toml"
)

type tomlConfig struct {
	Profiles map[string]profile `toml:"profiles"`
}

type profile struct {
	Email           string   `toml:"email"`
	AuthType        string   `toml:"auth_type"`
	SessionDuration string   `toml:"session_duration,omitempty"`
	Policies        []policy `toml:"policies,omitempty"`
}

type policy struct {
	Effect           string                 `toml:"effect"`
	ID               string                 `toml:"id,omitempty"`
	PermissionGroups []permissionGroup      `toml:"permission_groups"`
	Resources        map[string]interface{} `toml:"resources"`
}

type permissionGroup struct {
	ID   string `toml:"id"`
	Name string `toml:"name,omitempty"`
}

var addCmd = &cobra.Command{
	Use:   "add [profile]",
	Short: "Add a new profile to your configuration and keychain",
	Long:  "",
	Example: `
  Add a new profile (you will be prompted for credentials)

    $ cf-vault add example-profile
`,
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) < 1 {
			return errors.New("requires a profile argument")
		}
		return nil
	},
	PreRun: func(cmd *cobra.Command, args []string) {
		if verbose {
			log.SetLevel(log.DebugLevel)
			keyring.Debug = true
		}
	},
	Run: func(cmd *cobra.Command, args []string) {
		profileName := strings.TrimSpace(args[0])
		sessionDuration, _ := cmd.Flags().GetString("session-duration")
		profileTemplate, _ := cmd.Flags().GetString("profile-template")

		reader := bufio.NewReader(os.Stdin)
		fmt.Print("Email address: ")
		emailAddress, _ := reader.ReadString('\n')
		emailAddress = strings.TrimSpace(emailAddress)

		fmt.Print("Authentication value (API key or API token): ")
		byteAuthValue, err := terminal.ReadPassword(0)
		if err != nil {
			log.Fatal("unable to read authentication value: ", err)
		}
		authValue := string(byteAuthValue)
		fmt.Println()

		authType, err := determineAuthType(strings.TrimSpace(authValue))
		if err != nil {
			log.Fatal("failed to detect authentication type: ", err)
		}

		home, err := homedir.Dir()
		if err != nil {
			log.Fatal("unable to find home directory: ", err)
		}

		os.MkdirAll(home+defaultConfigDirectory, 0700)
		if _, err := os.Stat(home + defaultFullConfigPath); os.IsNotExist(err) {
			file, err := os.Create(home + defaultFullConfigPath)
			if err != nil {
				log.Fatal(err)
			}
			defer file.Close()
		}

		existingConfigFileContents, err := ioutil.ReadFile(home + defaultFullConfigPath)
		if err != nil {
			log.Fatal(err)
		}

		tomlConfigStruct := tomlConfig{}
		toml.Unmarshal(existingConfigFileContents, &tomlConfigStruct)

		// If this is the first profile, initialise the map.
		if len(tomlConfigStruct.Profiles) == 0 {
			tomlConfigStruct.Profiles = make(map[string]profile)
		}

		newProfile := profile{
			Email:    emailAddress,
			AuthType: authType,
		}

		if sessionDuration != "" {
			newProfile.SessionDuration = sessionDuration
		} else {
			log.Debug("session-duration was not set, not using short lived tokens")
		}

		var api *cloudflare.API
		if authType == "api_token" {
			api, err = cloudflare.NewWithAPIToken(authValue)
			if err != nil {
				log.Fatal(err)
			}
		} else {
			api, err = cloudflare.New(authValue, emailAddress)
			if err != nil {
				log.Fatal(err)
			}
		}

		if profileTemplate != "" {
			// The policies require that one of the resources is the current user.
			// This leads to a potential chicken/egg scenario where the user doesn't
			// valid credentials but needs them to generate the resources. We
			// intentionally spit out `Debug` and `Fatal` messages here to show the
			// original error *and* the friendly version of how to resolve it.
			userDetails, err := api.UserDetails(context.Background())
			if err != nil {
				log.Debug(err)
				log.Fatal("failed to fetch user ID from the Cloudflare API which is required to generate the predefined short lived token policies. If you are using API tokens, please allow the permission to access your user details and try again.")
			}

			generatedPolicy, err := generatePolicy(profileTemplate, userDetails.ID)
			if err != nil {
				log.Fatal(err)
			}
			newProfile.Policies = generatedPolicy
		}

		log.Debugf("new profile: %+v", newProfile)
		tomlConfigStruct.Profiles[profileName] = newProfile

		configFile, err := os.OpenFile(home+defaultFullConfigPath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0700)
		if err != nil {
			log.Fatal("failed to open file at ", home+defaultFullConfigPath)
		}
		defer configFile.Close()
		if err := toml.NewEncoder(configFile).Encode(tomlConfigStruct); err != nil {
			log.Fatal(err)
		}

		ring, err := keyring.Open(keyringDefaults)
		if err != nil {
			log.Fatalf("failed to open keyring backend: %s", strings.ToLower(err.Error()))
		}

		resp := ring.Set(keyring.Item{
			Key:  fmt.Sprintf("%s-%s", profileName, authType),
			Data: []byte(authValue),
		})

		if resp == nil {
			fmt.Println("\nSuccess! Credentials have been set and are now ready for use!")
		} else {
			// error of some sort
			log.Fatal("Error adding credentials to keyring: ", resp)
		}
	},
}

func determineAuthType(s string) (string, error) {
	if apiTokenMatch, _ := regexp.MatchString("[A-Za-z0-9-_]{40}", s); apiTokenMatch {
		log.Debug("API token detected")
		return "api_token", nil
	} else if apiKeyMatch, _ := regexp.MatchString("[0-9a-f]{37}", s); apiKeyMatch {
		log.Debug("API key detected")
		return "api_key", nil
	} else {
		return "", errors.New("invalid API token or API key format")
	}
}

func generatePolicy(policyType, userID string) ([]policy, error) {
	readOnlyPolicy := []policy{
		{
			Effect:    "allow",
			Resources: map[string]interface{}{"com.cloudflare.api.account.*": "*"},
			PermissionGroups: []permissionGroup{
				{ID: "02b71f12bb0748e9af8126494e181342"},  // Magic Firewall Read
				{ID: "050531528b044d58bbb71666fef7c07c"},  // Page Shield Read
				{ID: "05880cd1bdc24d8bae0be2136972816b"},  // Workers Tail Read
				{ID: "07bea2220b2343fa9fae15656c0d8e88"},  // Bot Management Read
				{ID: "08e61dabe81a422dab0dea6fdef1a98a"},  // Access: Custom Page Read
				{ID: "0cf6473ad41449e7b7b743d14fc20c60"},  // Images Read
				{ID: "0f4841f80adb4bada5a09493300e7f8d"},  // Access: Device Posture Read
				{ID: "1047880d37b649b49db4a504a245896f"},  // Email Security DMARC Reports Read
				{ID: "192192df92ee43ac90f2aeeffce67e35"},  // D1 Read
				{ID: "1a71c399035b4950a1bd1466bbe4f420"},  // Workers Scripts Read
				{ID: "1b1ea24cf0904d33903f0cc7e54e280f"},  // Zone Versioning Read
				{ID: "1b600d9d8062443e986a973f097e728a"},  // Email Routing Rules Read
				{ID: "2072033d694d415a936eaeb94e6405b8"},  // Workers Routes Read
				{ID: "20e5ea084b2f491c86b8d8d90abff905"},  // Config Settings Read
				{ID: "211a4c0feb3e43b3a2d41f1443a433e7"},  // Zone Transform Rules Read
				{ID: "212c9ff247b9406d990c017482afb3a5"},  // IOT Read
				{ID: "26bc23f853634eb4bff59983b9064fde"},  // Access: Organizations, Identity Providers, and Groups Read
				{ID: "27beb7f8333b41e2b946f0e23cd8091e"},  // IP Prefixes: Read
				{ID: "29eefa0805f94fdfae2b058b5b52f319"},  // Disable ESC Read
				{ID: "319f5059d33a410da0fac4d35a716157"},  // Managed headers Read
				{ID: "3245da1cf36c45c3847bb9b483c62f97"},  // Cache Settings Read
				{ID: "3a46c728a0a040d5a65cd8e2f3bc6935"},  // Magic Firewall Packet Captures - Read PCAPs API
				{ID: "3b376e0aa52c41cbb6afc9cab945afa8"},  // Cloudflare DEX Read
				{ID: "3d85e9514f944bb4912c5871d92e5af5"},  // Magic Network Monitoring Config Read
				{ID: "3f376c8e6f764a938b848bd01c8995c4"},  // Teams Read
				{ID: "429a068902904c5a9ed9fc267c67da9a"},  // Mass URL Redirects Read
				{ID: "4657621393f94f83b8ef94adba382e48"},  // L4 DDoS Managed Ruleset Read
				{ID: "4ec32dfcb35641c5bb32d5ef1ab963b4"},  // Firewall Services Read
				{ID: "4f1071168de8466e9808de86febfc516"},  // Account Rule Lists Read
				{ID: "4f3196a5c95747b6ad82e34e1d0a694f"},  // Access: Certificates Read
				{ID: "517b21aee92c4d89936c976ba6e4be55"},  // Zone Settings Read
				{ID: "51be404b56244056868226263a44a632"},  // Bot Management Feedback Report Read
				{ID: "5272e56105d04b5897466995b9bd4643"},  // Email Routing Addresses Read
				{ID: "56b2af4817c84ad99187911dc3986c23"},  // Account WAF Read
				{ID: "58abbad6d2ce40abb2594fbe932a2e0e"},  // Rule Policies Read
				{ID: "595409c54a24444b80a495620b2d614c"},  // Select Configuration Read
				{ID: "5bdbde7e76144204a244274eac3eb0eb"},  // Zaraz Read
				{ID: "5d613a610b294788a29572aaac2f254d"},  // URL Scanner Read
				{ID: "5d78fd7895974fd0bdbbbb079482721b"},  // Turnstile Sites Read
				{ID: "5f48a472240a4b489a21d43bd19a06e1"},  // DNS Firewall Read
				{ID: "6a315a56f18441e59ed03352369ae956"},  // Logs Read
				{ID: "6b60a5a87cae475da7e76e77e4209dd5"},  // HTTP Applications Read
				{ID: "6ced5d0d69b1422396909a62c38ab41b"},  // API Gateway Read
				{ID: "74c654eb4aac40e28d6c6caa4c5aeb3d"},  // Snippets Read
				{ID: "7b32a91ece3140d4b3c2c56f23fc8e35"},  // Origin Read
				{ID: "7b7216b327b04b8fbc8f524e1f9b7531"},  // SSL and Certificates Read
				{ID: "7cf72faf220841aabcfdfab81c43c4f6"},  // Billing Read
				{ID: "7ea222f6d5064cfa89ea366d7c1fee89"},  // Access: Apps and Policies Read
				{ID: "82e64a83756745bbbb1c9c2701bf816b"},  // DNS Read
				{ID: "853643ed57244ed1a05a7c024af9ab5a"},  // Sanitize Read
				{ID: "8b47d2786a534c08a1f94ee8f9f599ef"},  // Workers KV Storage Read
				{ID: "8e31f574901c42e8ad89140b28d42112"},  // Web3 Hostnames Read
				{ID: "91f7ce32fa614d73b7e1fc8f0e78582b"},  // Access: Service Tokens Read
				{ID: "945315185a8f40518bf3e9e6d0bee126"},  // Domain Page Shield Read
				{ID: "967ecf860a244dd1911a0331a0af582a"},  // Magic Transit Prefix Read
				{ID: "99ff99e4e30247a99d3777a8c4c18541"},  // Access: SSH Auditing CA Read
				{ID: "9ade9cfc8f8949bcb2371be2f0ec8db1"},  // China Network Steering Read
				{ID: "9c88f9c5bce24ce7af9a958ba9c504db"},  // Analytics Read
				{ID: "9d24387c6e8544e2bc4024a03991339f"},  // Load Balancing: Monitors and Pools Read
				{ID: "a2431ca73b7d41f99c53303027392586"},  // Custom Pages Read
				{ID: "a2b55cd504d44ef18b7ba6a7f2b8fbb1"},  // Custom Errors Read
				{ID: "a7a233f9604845c787d4c8c39ac09c21"},  // Account: SSL and Certificates Read
				{ID: "a9a99455bf3245f6a5a244f909d74830"},  // Transform Rules Read
				{ID: "af1c363c35ba45b9a8c682ae50eb3f99"},  // DDoS Protection Read
				{ID: "b05b28e839c54467a7d6cba5d3abb5a3"},  // Access: Audit Logs Read
				{ID: "b415b70a4fd1412886f164451f20405c"},  // Page Rules Read
				{ID: "b4992e1108244f5d8bfbd5744320c2e1"},  // Workers R2 Storage Read
				{ID: "b89a480218d04ceb98b4fe57ca29dc1f"},  // Account Analytics Read
				{ID: "c1fde68c7bcc44588cbb6ddbc16d6480"},  // Account Settings Read
				{ID: "c49f8d15f9f44885a544d945ef5aa6ae"},  // HTTP DDoS Managed Ruleset Read
				{ID: "c4a30cd58c5d42619c86a3c36c441e2d"},  // Logs Read
				{ID: "c57ea647ef654b47bc8944fa739b570d"},  // Account Custom Pages Read
				{ID: "c8fed203ed3043cba015a93ad1616f1f"},  // Zone Read
				{ID: "cab5202d07ef47beae788e6bc95cb6fe"},  // Waiting Rooms Read
				{ID: "d8e12db741544d1586ec1d6f5d3c7786"},  // Dynamic URL Redirects Read
				{ID: "dbc512b354774852af2b5a5f4ba3d470"},  // Zone WAF Read
				{ID: "de21485a24744b76a004aa153898f7fe"},  // Stream Read
				{ID: "de7a688cc47d43bd9ea700b467a09c96"},  // Account Firewall Access Rules Read
				{ID: "df1577df30ee46268f9470952d7b0cdf"},  // Intel Read
				{ID: "e199d584e69344eba202452019deafe3"},  // Disable ESC Read
				{ID: "e247aedd66bd41cc9193af0213416666"},  // Pages Read
				{ID: "e763fae6ee95443b8f56f19213c5f2a5"},  // IP Prefixes: BGP On Demand Read
				{ID: "e9a975f628014f1d85b723993116f7d5"},  // Load Balancers Read
				{ID: "eb258a38ea634c86a0c89da6b27cb6b6"},  // Access: Apps and Policies Read
				{ID: "eb56a6953c034b9d97dd838155666f06"},  // Account API Tokens Read
				{ID: "eeffa4d16812430cb4a0ae9e7f46fc24"},  // Constellation Read
				{ID: "efea2ab8357b47888938f101ae5e053f"},  // Argo Tunnel Read
				{ID: "f3604047d46144d2a3e9cf4ac99d7f16"},  // Allow Request Tracer Read
				{ID: "fac65912d42144aa86b7dd33281bf79e"},  // Health Checks Read
				{ID: "fb39996ee9044d2a8725921e02744b39"},  // Account Rulesets Read
				{ID: "fd7f886c75a244389e892c4c3c068292"},  // Pubsub Configuration Read
			},
		},
		{
			Effect:    "allow",
			Resources: map[string]interface{}{"com.cloudflare.api.account.zone.*": "*"},
			PermissionGroups: []permissionGroup{
				{ID: "07bea2220b2343fa9fae15656c0d8e88"},  // Bot Management Read
				{ID: "1047880d37b649b49db4a504a245896f"},  // Email Security DMARC Reports Read
				{ID: "1b1ea24cf0904d33903f0cc7e54e280f"},  // Zone Versioning Read
				{ID: "1b600d9d8062443e986a973f097e728a"},  // Email Routing Rules Read
				{ID: "2072033d694d415a936eaeb94e6405b8"},  // Workers Routes Read
				{ID: "20e5ea084b2f491c86b8d8d90abff905"},  // Config Settings Read
				{ID: "211a4c0feb3e43b3a2d41f1443a433e7"},  // Zone Transform Rules Read
				{ID: "319f5059d33a410da0fac4d35a716157"},  // Managed headers Read
				{ID: "3245da1cf36c45c3847bb9b483c62f97"},  // Cache Settings Read
				{ID: "4ec32dfcb35641c5bb32d5ef1ab963b4"},  // Firewall Services Read
				{ID: "517b21aee92c4d89936c976ba6e4be55"},  // Zone Settings Read
				{ID: "51be404b56244056868226263a44a632"},  // Bot Management Feedback Report Read
				{ID: "5bdbde7e76144204a244274eac3eb0eb"},  // Zaraz Read
				{ID: "6ced5d0d69b1422396909a62c38ab41b"},  // API Gateway Read
				{ID: "74c654eb4aac40e28d6c6caa4c5aeb3d"},  // Snippets Read
				{ID: "7b32a91ece3140d4b3c2c56f23fc8e35"},  // Origin Read
				{ID: "7b7216b327b04b8fbc8f524e1f9b7531"},  // SSL and Certificates Read
				{ID: "82e64a83756745bbbb1c9c2701bf816b"},  // DNS Read
				{ID: "853643ed57244ed1a05a7c024af9ab5a"},  // Sanitize Read
				{ID: "8e31f574901c42e8ad89140b28d42112"},  // Web3 Hostnames Read
				{ID: "945315185a8f40518bf3e9e6d0bee126"},  // Domain Page Shield Read
				{ID: "9c88f9c5bce24ce7af9a958ba9c504db"},  // Analytics Read
				{ID: "a2431ca73b7d41f99c53303027392586"},  // Custom Pages Read
				{ID: "a2b55cd504d44ef18b7ba6a7f2b8fbb1"},  // Custom Errors Read
				{ID: "b415b70a4fd1412886f164451f20405c"},  // Page Rules Read
				{ID: "c49f8d15f9f44885a544d945ef5aa6ae"},  // HTTP DDoS Managed Ruleset Read
				{ID: "c4a30cd58c5d42619c86a3c36c441e2d"},  // Logs Read
				{ID: "c8fed203ed3043cba015a93ad1616f1f"},  // Zone Read
				{ID: "cab5202d07ef47beae788e6bc95cb6fe"},  // Waiting Rooms Read
				{ID: "d8e12db741544d1586ec1d6f5d3c7786"},  // Dynamic URL Redirects Read
				{ID: "dbc512b354774852af2b5a5f4ba3d470"},  // Zone WAF Read
				{ID: "e199d584e69344eba202452019deafe3"},  // Disable ESC Read
				{ID: "e9a975f628014f1d85b723993116f7d5"},  // Load Balancers Read
				{ID: "eb258a38ea634c86a0c89da6b27cb6b6"},  // Access: Apps and Policies Read
				{ID: "fac65912d42144aa86b7dd33281bf79e"},  // Health Checks Read
			},
		},
		{
			Effect:    "allow",
			Resources: map[string]interface{}{"com.cloudflare.api.user." + userID: "*"},
			PermissionGroups: []permissionGroup{
				{ID: "0cc3a61731504c89b99ec1be78b77aa0"},  // API Tokens Read
				{ID: "3518d0f75557482e952c6762d3e64903"},  // Memberships Read
				{ID: "8acbe5bb0d54464ab867149d7f7cf8ac"},  // User Details Read
			},
		},
	}

	writeEverythingPolicy := []policy{
		{
			Effect:    "allow",
			Resources: map[string]interface{}{"com.cloudflare.api.account.*": "*"},
			PermissionGroups: []permissionGroup{
				{ID: "06f0526e6e464647bd61b63c54935235"},  // Config Settings Write
				{ID: "094547ab6e77498c8c4dfa87fadd5c51"},  // Apps Write
				{ID: "09b2857d1c31407795e75e3fed8617a1"},  // D1 Write
				{ID: "09c77baecb6341a2b1ca2c62b658d290"},  // Magic Network Monitoring Config Write
				{ID: "0ac90a90249747bca6b047d97f0803e9"},  // Zone Transform Rules Write
				{ID: "0bc09a3cd4b54605990df4e307f138e1"},  // Magic Transit Prefix Write
				{ID: "0fd9d56bc2da43ad8ea22d610dd8cab1"},  // Managed headers Write
				{ID: "18555e39c5ba40d284dde87eda845a90"},  // Disable ESC Write
				{ID: "1af1fa2adc104452b74a9a3364202f20"},  // Account Settings Write
				{ID: "1e13c5124ca64b72b1969a67e8829049"},  // Access: Apps and Policies Write
				{ID: "2002629aaff0454085bf5a201ed70a72"},  // Bot Management Feedback Report Write
				{ID: "235eac9bb64942b49cb805cc851cb000"},  // Select Configuration Write
				{ID: "24fc124dc8254e0db468e60bf410c800"},  // Waiting Rooms Write
				{ID: "28f4b596e7d643029c524985477ae49a"},  // Workers Routes Write
				{ID: "29d3afbfd4054af9accdd1118815ed05"},  // Access: Certificates Write
				{ID: "2a400bcb29154daab509fe07e3facab0"},  // URL Scanner Write
				{ID: "2ae23e4939d54074b7d252d27ce75a77"},  // IP Prefixes: BGP On Demand Write
				{ID: "2edbf20661fd4661b0fe10e9e12f485c"},  // Account Rule Lists Write
				{ID: "2eee71c9364c4cacaf469e8370f09056"},  // Email Security DMARC Reports Write
				{ID: "2fc1072ee6b743828db668fcb3f9dee7"},  // Access: Device Posture Write
				{ID: "3030687196b94b638145a3953da2b699"},  // Zone Settings Write
				{ID: "3a1e1ef09dd34271bb44fc4c6a419952"},  // Cloudflare DEX
				{ID: "3b94c49258ec4573b06d51d99b6416c0"},  // Bot Management Write
				{ID: "3e0b5820118e47f3922f7c989e673882"},  // Logs Write
				{ID: "43137f8d07884d3198dc0ee77ca6e79b"},  // Firewall Services Write
				{ID: "440e6958bcc947329f8d56328d7322ce"},  // Page Shield
				{ID: "4736c02a9f224c8196ae5b127beae78c"},  // HTTP Applications Write
				{ID: "4755a26eedb94da69e1066d98aa820be"},  // DNS Write
				{ID: "4e5fd8ac327b4a358e48c66fcbeb856d"},  // Access: Custom Page Write
				{ID: "4ea7d6421801452dbf07cef853a5ef39"},  // Magic Firewall Packet Captures - Write PCAPs API
				{ID: "56907406c3d548ed902070ec4df0e328"},  // Account Rulesets Write
				{ID: "5bc3f8b21c554832afc660159ab75fa4"},  // Account API Tokens Write
				{ID: "5ea6da42edb34811a78d1b007557c0ca"},  // Web3 Hostnames Write
				{ID: "6134079371904d8ebd77931c8ca07e50"},  // Domain Page Shield
				{ID: "618ec6c64a3a42f8b08bdcb147ded4e4"},  // Images Write
				{ID: "61ddc58f1da14f95b33b41213360cbeb"},  // Rule Policies Write
				{ID: "6c80e02421494afc9ae14414ed442632"},  // Billing Write
				{ID: "6c9d1cfcfc6840a987d1b5bfb880a841"},  // Access: Apps and Policies Revoke
				{ID: "6d7f2f5f5b1d4a0e9081fdc98d432fd1"},  // Load Balancers Write
				{ID: "6db4e222e21248ac96a3f4c2a81e3b41"},  // Access: Apps and Policies Revoke
				{ID: "7121a0c7e9ed46e3829f9cca2bb572aa"},  // Access: Organizations, Identity Providers, and Groups Revoke
				{ID: "714f9c13a5684c2885a793f5edb36f59"},  // Stream Write
				{ID: "74e1036f577a48528b78d2413b40538d"},  // Dynamic URL Redirects Write
				{ID: "755c05aa014b4f9ab263aa80b8167bd8"},  // Turnstile Sites Write
				{ID: "79b3ec0d10ce4148a8f8bdc0cc5f97f2"},  // Email Routing Rules Write
				{ID: "7a4c3574054a4d0ba7c692893ba8bdd4"},  // L4 DDoS Managed Ruleset Write
				{ID: "7c81856725af47ce89a790d5fb36f362"},  // Constellation Write
				{ID: "865ebd55bc6d4b109de6813eccfefd13"},  // IOT Write
				{ID: "87065285ab38463481e72815eefd18c3"},  // Page Shield Write
				{ID: "89bb8c37d46042e98b84560eaaa6379f"},  // Sanitize Write
				{ID: "89d5bf002389496e9994b8c30608b5d0"},  // Zaraz Edit
				{ID: "8a9d35a7c8504208ad5c3e8d58e6162d"},  // Account Custom Pages Write
				{ID: "8bd1dac84d3d43e7bfb43145f010a15c"},  // Magic Firewall Write
				{ID: "8d28297797f24fb8a0c332fe0866ec89"},  // Pages Write
				{ID: "8e6ed1ef6e864ad0ae477ceffa5aa5eb"},  // Magic Network Monitoring Admin
				{ID: "910b6ecca1c5411bb894e787362d1312"},  // Pubsub Configuration Write
				{ID: "9110d9dd749e464fb9f3961a2064efc5"},  // Disable ESC Write
				{ID: "92209474242d459690e2cdb1985eaa6c"},  // Intel Write
				{ID: "92b8234e99f64e05bbbc59e1dc0f76b6"},  // IP Prefixes: Write
				{ID: "92c8dcd551cc42a6a57a54e8f8d3f3e3"},  // Cloudflare DEX Write
				{ID: "959972745952452f8be2452be8cbb9f2"},  // Access: Apps and Policies Write
				{ID: "96163bd1b0784f62b3e44ed8c2ab1eb6"},  // Logs Write
				{ID: "9ff81cbbe65c400b97d92c3c1033cab6"},  // Cache Settings Write
				{ID: "a1a6298e52584c8fb6313760a30c681e"},  // Zero Trust: Seats Write
				{ID: "a1c0fec57cf94af79479a6d827fa518c"},  // Access: Service Tokens Write
				{ID: "a416acf9ef5a4af19fb11ed3b96b1fe6"},  // Account Firewall Access Rules Write
				{ID: "a4308c6855c84eb2873e01b6cc85cbb3"},  // Origin Write
				{ID: "a9dba34cf5814d4ab2007b4ada0045bd"},  // Custom Errors Write
				{ID: "abe78e2276664f4db588c1f675a77486"},  // Mass URL Redirects Write
				{ID: "ae16e88bc7814753a1894c7ce187ab72"},  // Transform Rules Write
				{ID: "b33f02c6f7284e05a6f20741c0bb0567"},  // Teams Write
				{ID: "b88a3aa889474524bccea5cf18f122bf"},  // HTTP DDoS Managed Ruleset Write
				{ID: "bf7481a1826f439697cb59a20b22293e"},  // Workers R2 Storage Write
				{ID: "bfe0d8686a584fa680f4c53b5eb0de6d"},  // Access: Organizations, Identity Providers, and Groups Write
				{ID: "c03055bc037c4ea9afb9a9f104b7b721"},  // SSL and Certificates Write
				{ID: "c07321b023e944ff818fec44d8203567"},  // Argo Tunnel Write
				{ID: "c244ec076974430a88bda1cdd992d0d9"},  // Custom Pages Write
				{ID: "c6f6338ceae545d0b90daaa1fed855e6"},  // China Network Steering Write
				{ID: "c9915d86fbff46af9dd945c0a882294b"},  // Zone Versioning Write
				{ID: "cde8c82463b6414ca06e46b9633f52a6"},  // Account WAF Write
				{ID: "cdeb15b336e640a2965df8c65052f1e0"},  // Zaraz Admin
				{ID: "d2a1802cc9a34e30852f8b33869b2f3c"},  // Load Balancing: Monitors and Pools Write
				{ID: "d30c9ad8b5224e7cb8d41bcb4757effc"},  // Access: SSH Auditing CA Write
				{ID: "d44ed14bcc4340b194d3824d60edad3f"},  // DDoS Protection Write
				{ID: "da6d2d6f2ec8442eaadda60d13f42bca"},  // DNS Firewall Write
				{ID: "dadeaf3abdf14126a77a35e0c92fc36e"},  // Snippets Write
				{ID: "db37e5f1cb1a4e1aabaef8deaea43575"},  // Account: SSL and Certificates Write
				{ID: "e086da7e2179491d91ee5f35b3ca210a"},  // Workers Scripts Write
				{ID: "e0dc25a0fbdf4286b1ea100e3256b0e3"},  // Health Checks Write
				{ID: "e17beae8b8cb423a99b1730f21238bed"},  // Cache Purge
				{ID: "e4589eb09e63436686cd64252a3aebeb"},  // Email Routing Addresses Write
				{ID: "e6d2666161e84845a636613608cee8d5"},  // Zone Write
				{ID: "ed07f6c337da4195b4e72a1fb2c6bcae"},  // Page Rules Write
				{ID: "efb81b5cd37d49f3be1da9363a6d7a19"},  // Teams Report
				{ID: "f0235726de25444a84f704b7c93afadf"},  // API Gateway Write
				{ID: "f7f0eda5697f475c90846e879bab8666"},  // Workers KV Storage Write
				{ID: "fb6778dc191143babbfaa57993f1d275"},  // Zone WAF Write
			},
		},
		{
			Effect:    "allow",
			Resources: map[string]interface{}{"com.cloudflare.api.account.zone.*": "*"},
			PermissionGroups: []permissionGroup{
				{ID: "06f0526e6e464647bd61b63c54935235"},  // Config Settings Write
				{ID: "094547ab6e77498c8c4dfa87fadd5c51"},  // Apps Write
				{ID: "0ac90a90249747bca6b047d97f0803e9"},  // Zone Transform Rules Write
				{ID: "0fd9d56bc2da43ad8ea22d610dd8cab1"},  // Managed headers Write
				{ID: "2002629aaff0454085bf5a201ed70a72"},  // Bot Management Feedback Report Write
				{ID: "24fc124dc8254e0db468e60bf410c800"},  // Waiting Rooms Write
				{ID: "28f4b596e7d643029c524985477ae49a"},  // Workers Routes Write
				{ID: "2eee71c9364c4cacaf469e8370f09056"},  // Email Security DMARC Reports Write
				{ID: "3030687196b94b638145a3953da2b699"},  // Zone Settings Write
				{ID: "3b94c49258ec4573b06d51d99b6416c0"},  // Bot Management Write
				{ID: "3e0b5820118e47f3922f7c989e673882"},  // Logs Write
				{ID: "43137f8d07884d3198dc0ee77ca6e79b"},  // Firewall Services Write
				{ID: "4755a26eedb94da69e1066d98aa820be"},  // DNS Write
				{ID: "5ea6da42edb34811a78d1b007557c0ca"},  // Web3 Hostnames Write
				{ID: "6134079371904d8ebd77931c8ca07e50"},  // Domain Page Shield
				{ID: "6d7f2f5f5b1d4a0e9081fdc98d432fd1"},  // Load Balancers Write
				{ID: "6db4e222e21248ac96a3f4c2a81e3b41"},  // Access: Apps and Policies Revoke
				{ID: "74e1036f577a48528b78d2413b40538d"},  // Dynamic URL Redirects Write
				{ID: "79b3ec0d10ce4148a8f8bdc0cc5f97f2"},  // Email Routing Rules Write
				{ID: "87065285ab38463481e72815eefd18c3"},  // Page Shield Write
				{ID: "89bb8c37d46042e98b84560eaaa6379f"},  // Sanitize Write
				{ID: "89d5bf002389496e9994b8c30608b5d0"},  // Zaraz Edit
				{ID: "9110d9dd749e464fb9f3961a2064efc5"},  // Disable ESC Write
				{ID: "959972745952452f8be2452be8cbb9f2"},  // Access: Apps and Policies Write
				{ID: "9ff81cbbe65c400b97d92c3c1033cab6"},  // Cache Settings Write
				{ID: "a4308c6855c84eb2873e01b6cc85cbb3"},  // Origin Write
				{ID: "a9dba34cf5814d4ab2007b4ada0045bd"},  // Custom Errors Write
				{ID: "b88a3aa889474524bccea5cf18f122bf"},  // HTTP DDoS Managed Ruleset Write
				{ID: "c03055bc037c4ea9afb9a9f104b7b721"},  // SSL and Certificates Write
				{ID: "c244ec076974430a88bda1cdd992d0d9"},  // Custom Pages Write
				{ID: "c9915d86fbff46af9dd945c0a882294b"},  // Zone Versioning Write
				{ID: "cdeb15b336e640a2965df8c65052f1e0"},  // Zaraz Admin
				{ID: "dadeaf3abdf14126a77a35e0c92fc36e"},  // Snippets Write
				{ID: "e0dc25a0fbdf4286b1ea100e3256b0e3"},  // Health Checks Write
				{ID: "e17beae8b8cb423a99b1730f21238bed"},  // Cache Purge
				{ID: "e6d2666161e84845a636613608cee8d5"},  // Zone Write
				{ID: "ed07f6c337da4195b4e72a1fb2c6bcae"},  // Page Rules Write
				{ID: "f0235726de25444a84f704b7c93afadf"},  // API Gateway Write
				{ID: "fb6778dc191143babbfaa57993f1d275"},  // Zone WAF Write
			},
		},
		{
			Effect:    "allow",
			Resources: map[string]interface{}{"com.cloudflare.api.user." + userID: "*"},
			PermissionGroups: []permissionGroup{
				{ID: "55a5e17cc99e4a3fa1f3432d262f2e55"},  // User Details Write
				{ID: "9201bc6f42d440968aaab0c6f17ebb1d"},  // Memberships Write
			},
		},
	}

	switch policyType {
	case "write-everything":
		log.Debug("configuring a write-everything template")
		return writeEverythingPolicy, nil
	case "read-only":
		log.Debug("configuring a read-only template")
		return readOnlyPolicy, nil
	}

	return nil, fmt.Errorf("unable to generate policy for %q, valid policy names: [read-only, write-everything]", policyType)
}
