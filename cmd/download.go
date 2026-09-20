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

// runDownload 는 내장 목록에서 루트 인증서를 하나 골라 내려받는다.
func runDownload() error {
	var r internal.RootYaml
	if err := internal.ParsingYaml(&r); err != nil {
		return panicRed(err)
	}

	rootName, err := internal.AskSelect("Select root certificate", r.Root.GetNameListOwnURL())
	if err != nil {
		return panicRed(err)
	}

	url := r.Root.FindURL(rootName)
	fileName := fmt.Sprintf("%s.pem", strings.ReplaceAll(rootName, " ", ""))
	if err := internal.DownloadCertificate(url, fileName); err != nil {
		return panicRed(err)
	}

	fmt.Printf("%s %s %s",
		color.HiBlackString("🎉 [ROOT CERTIFICATE]"),
		color.HiWhiteString(fileName),
		color.HiGreenString("Download Complete 🎉\n"))
	return nil
}

func init() {
	rootCmd.AddCommand(downloadCommand)
}
