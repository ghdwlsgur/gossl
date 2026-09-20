package main

import (
	"github.com/ghdwlsgur/gossl/cmd"
)

// gosslVersion 은 릴리스 빌드에서 ldflags 로 주입된다.
// 로컬 빌드에서는 dev 로 남는다.
var gosslVersion = "dev"

func main() {
	cmd.Execute(gosslVersion)
}
