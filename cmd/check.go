package cmd

import (
	"fmt"

	"github.com/ghdwlsgur/gossl/internal"
	"github.com/spf13/cobra"
)

var (
	checkCommand = &cobra.Command{
		Use:   "check",
		Short: "Check the certificate of domain",
		Long:  "Check the certificate of domain",
		Run: func(cmd *cobra.Command, args []string) {
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
			if len(ips) == 0 {
				panicRed(fmt.Errorf("no IPv4 address found for %s, this domain may be IPv6 only", domain))
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
