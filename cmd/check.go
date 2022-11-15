package cmd

import (
	"github.com/ghdwlsgur/cert-check/internal"
	"github.com/spf13/cobra"
)

var (
	err error
)

var (
	checkCommand = &cobra.Command{
		Use:   "check",
		Short: "test",
		Long:  "test",
		Run: func(_ *cobra.Command, _ []string) {

			domain, err := internal.AskInput("What is your domain ?", 1)
			if err != nil {
				panicRed(err)
			}

			targetDomain, err := internal.AskInput("What is your target domain ?", 1)
			if err != nil {
				panicRed(err)
			}

			ips, err := internal.GetRecord(domain)
			if err != nil {
				panicRed(err)
			}

			for {
				_, err = internal.Validate(ips, domain, targetDomain)
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
