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
		RunE: func(cmd *cobra.Command, args []string) error {
			var (
				err error
			)

			domain, err := setDomain(args)
			if err != nil {
				return panicRed(err)
			}

			checkHostErr := internal.GetHost(domain)
			if checkHostErr != nil {
				return panicRed(checkHostErr)
			}

			ips, err := internal.GetRecordIPv4(domain)
			if err != nil {
				return panicRed(err)
			}
			if len(ips) == 0 {
				return panicRed(fmt.Errorf("no IPv4 address found for %s, this domain may be IPv6 only", domain))
			}

			err = internal.GetCertificate(domain, ips[0])
			if err != nil {
				return panicRed(err)
			}
			return nil
		},
	}
)

func init() {
	rootCmd.AddCommand(checkCommand)
}
