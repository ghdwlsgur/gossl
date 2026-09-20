package cmd

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

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

// Run 은 명령을 실행하고 종료 코드를 돌려준다.
//
// 프로세스를 끝내지 않으므로 테스트가 직접 부를 수 있다. 실제 종료는
// Execute 가 맡는다.
func Run(version string, args []string, out, errOut io.Writer) int {
	rootCmd.Version = version
	rootCmd.SilenceErrors = true
	rootCmd.SilenceUsage = true
	rootCmd.SetArgs(args)
	rootCmd.SetOut(out)
	rootCmd.SetErr(errOut)
	resetFlags(rootCmd)

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(errOut, err)
		return 1
	}
	return 0
}

// resetFlags 는 이전 호출이 남긴 플래그 상태를 되돌린다.
//
// rootCmd 는 패키지 전역이라 한 프로세스에서 Run 을 두 번 부르면 앞선
// 호출의 --help 나 --version 이 그대로 남아 다음 호출을 오염시킨다.
// 실행 파일에서는 한 번만 부르므로 드러나지 않지만, 테스트에서는 호출
// 순서에 따라 결과가 달라진다.
func resetFlags(cmd *cobra.Command) {
	cmd.Flags().VisitAll(func(f *pflag.Flag) {
		if !f.Changed {
			return
		}
		_ = f.Value.Set(f.DefValue)
		f.Changed = false
	})
	for _, sub := range cmd.Commands() {
		resetFlags(sub)
	}
}

// Execute 는 Run 의 결과를 종료 코드로 바꾼다.
//
// 성공일 때 os.Exit 을 부르지 않는 이유는, 호출부인 main 이 정상 반환으로
// 끝나야 테스트가 main 을 부를 수 있기 때문이다.
func Execute(version string) {
	if code := Run(version, os.Args[1:], os.Stdout, os.Stderr); code != 0 {
		os.Exit(code)
	}
}
