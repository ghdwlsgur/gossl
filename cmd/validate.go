package cmd

import (
	"fmt"

	"github.com/ghdwlsgur/gossl/internal"
	"github.com/spf13/cobra"
)

func setDomain(args []string) (string, error) {
	if len(args) < 1 || args[0] == "" {
		return "", fmt.Errorf("please enter your domain. ex) gossl validate naver.com")
	}
	return args[0], nil
}

var (
	validateCommand = &cobra.Command{
		Use:   "validate",
		Short: "Check the certificate information applied to the domain.",
		Long:  "Check the certificate information applied to the domain.",
		Run: func(_ *cobra.Command, args []string) {
			var (
				err error
			)

			domain, err := setDomain(args)
			if err != nil {
				panicRed(err)
			}

			checkHostErr := internal.GetHost(domain)
			if checkHostErr != nil {
				panicRed(checkHostErr)
			}

			ips, err := internal.GetRecordIPv4(domain)
			if err != nil {
				panicRed(err)
			}

			for _, ip := range ips {
				err = internal.GetCertificateInfo(ip, domain)
				if err != nil {
					panicRed(err)
				}
			}
		},
	}
)

func init() {
	rootCmd.AddCommand(validateCommand)
}
