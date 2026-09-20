package cmd

import (
	"github.com/ghdwlsgur/gossl/internal"
	"github.com/spf13/cobra"
)

var (
	checkCommand = &cobra.Command{
		Use:   "check",
		Short: "Check the certificate of domain",
		Long:  "Check the certificate of domain",
		RunE: func(_ *cobra.Command, args []string) error {
			return runCheck(args)
		},
	}
)

// runCheck 은 도메인의 A 레코드 중 첫 주소에 붙어 인증서를 보여준다.
func runCheck(args []string) error {
	domain, ips, err := resolveIPv4(args)
	if err != nil {
		return panicRed(err)
	}

	if err := internal.GetCertificate(domain, ips[0]); err != nil {
		return panicRed(err)
	}
	return nil
}

func init() {
	rootCmd.AddCommand(checkCommand)
}
