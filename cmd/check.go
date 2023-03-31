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

			err = internal.GetCertificate(domain, ips[0])
			if err != nil {
				panicRed(err)
			}
		},
	}
)

func init() {
	rootCmd.AddCommand(checkCommand)
}
