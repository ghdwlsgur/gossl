package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	which "github.com/hairyhenderson/go-which"
)

var (
	// PATH: /opt/homebrew/lib/gossl
	path = func() string {
		path := which.Which("gossl")
		path = strings.Replace(path, "bin", "lib", -1)
		return path
	}()

	// PATH: /opt/homebrew/lib/gossl/config.yaml
	_defaultYamlConfigPath = func(path, fileName string) string {
		return path + fileName
	}(path, "/config.yaml")
)

const (
	_configURL      = "https://raw.githubusercontent.com/ghdwlsgur/gossl/master/config/rootSSL.yaml"
	_configFileMode = 0755
)

var (
	rootCmd = &cobra.Command{
		Use:   "gossl",
		Short: `gossl is an interactive tool that allows you to integrate certificates, look up certificates and private keys, split integrated certificate files by root, intermediate, and leaf certificates, or view certificate information applied to a domain by A record. We will update the certificate format that changes for each ca.`,
		Long:  `gossl is an interactive tool that allows you to integrate certificates, look up certificates and private keys, split integrated certificate files by root, intermediate, and leaf certificates, or view certificate information applied to a domain by A record. We will update the certificate format that changes for each ca.`,
	}
)

// panicRed 는 오류를 붉게 감싸 반환한다.
//
// 예전에는 여기서 os.Exit(1) 을 불렀다. 오류 경로마다 프로세스가 죽어
// 테스트가 그 줄을 지날 수 없었고, defer 도 실행되지 않았다. 이제 오류를
// 돌려주고 최종 종료는 Execute 한 곳에서만 한다.
func panicRed(err error) error {
	return fmt.Errorf("%s", color.RedString("[err] %s", err.Error()))
}

func Execute(version string) {
	rootCmd.Version = version
	rootCmd.SilenceErrors = true
	rootCmd.SilenceUsage = true

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func initConfig() {
	if _, _, err := rootCmd.Find(os.Args[1:]); err != nil {
		fmt.Println(panicRed(err))
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)
}
