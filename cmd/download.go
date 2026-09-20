package cmd

import (
	"fmt"
	"strings"

	"github.com/fatih/color"
	"github.com/ghdwlsgur/gossl/internal"
	"github.com/spf13/cobra"
)

var (
	downloadCommand = &cobra.Command{
		Use:   "download",
		Short: "download root certificate",
		Long:  "download root certificate",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := cobra.NoArgs(cmd, args); err != nil {
				return panicRed(err)
			}
			return runDownload()
		},
	}
)

// runDownload 는 내장 번들에서 루트 인증서를 하나 골라 파일로 저장한다.
//
// 예전에는 손으로 관리한 목록의 벤더 URL 에서 내려받았다. 이제 인증서가
// 바이너리에 실려 있어 네트워크가 필요 없고, 받은 내용이 기대한 것인지
// 의심할 필요도 없다.
func runDownload() error {
	names, err := internal.RootCertificateNames()
	if err != nil {
		return panicRed(err)
	}

	rootName, err := internal.AskSelect("Select root certificate", names)
	if err != nil {
		return panicRed(err)
	}

	root, err := internal.FindRootCertificate(rootName)
	if err != nil {
		return panicRed(err)
	}

	fileName := fmt.Sprintf("%s.pem", sanitizeFileName(rootName))
	if _, err := internal.SaveRootCertificate(root, fileName); err != nil {
		return panicRed(err)
	}

	fmt.Printf("%s %s %s\n",
		color.HiBlackString("🎉 [ROOT CERTIFICATE]"),
		color.HiWhiteString(fileName),
		color.HiGreenString("Saved"))
	fmt.Printf("%s %s\n", color.HiBlackString("   SHA-256"), root.Fingerprint)
	return nil
}

// sanitizeFileName 은 인증서 이름을 파일명으로 쓸 수 있게 다듬는다.
// 공백을 없애고 경로 구분자 같은 글자를 밑줄로 바꾼다.
func sanitizeFileName(name string) string {
	replaced := strings.Map(func(r rune) rune {
		switch r {
		case ' ':
			return -1
		case '/', '\\', ':', '*', '?', '"', '<', '>', '|':
			return '_'
		}
		return r
	}, name)
	if replaced == "" {
		return "root"
	}
	return replaced
}

func init() {
	rootCmd.AddCommand(downloadCommand)
}
