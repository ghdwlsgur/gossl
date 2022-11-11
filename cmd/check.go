package cmd

import (
	"github.com/ghdwlsgur/cert-check/internal"
	"github.com/spf13/cobra"
)

var (
	domain    *internal.Domain
	reqDomain *internal.ReqDomain
	err       error
)

var (
	checkCommand = &cobra.Command{
		Use:   "check",
		Short: "test",
		Long:  "test",
		Run: func(_ *cobra.Command, _ []string) {

			domain, err = internal.AskDomain()
			if err != nil {
				panicRed(err)
			}

			reqDomain, err = internal.AskReqDomain()
			if err != nil {
				panicRed(err)
			}

			ips, err := internal.GetRecord(domain.Name)
			if err != nil {
				panicRed(err)
			}

			for {
				_, err = internal.Validate(ips, domain.Name, reqDomain.Name)
				if err != nil {
					panicRed(err)
				}
			}

		},
	}
)

func init() {
	rootCmd.AddCommand(checkCommand)
}
