//go:build tools
// +build tools

package tools

//go:generate go install golang.org/x/tools/gopls@latest
//go:generate go install golang.org/x/lint/golint@latest

import (
	_ "golang.org/x/lint/golint"
	_ "golang.org/x/tools/gopls"
)
