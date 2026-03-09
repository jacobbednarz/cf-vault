package main

import (
	"os"

	"github.com/jacobbednarz/cf-vault/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
