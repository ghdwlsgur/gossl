package cmd

import (
	"fmt"

	"github.com/ghdwlsgur/cert-check/internal"
	"github.com/spf13/cobra"
)

var (
	domain *internal.Domain
	err    error
	// response *internal.Response
)

var (
	checkCommand = &cobra.Command{
		Use:   "check",
		Short: "test",
		Long:  "test",
		Run: func(_ *cobra.Command, _ []string) {
			// ctx := context.Background()

			domain, err = internal.AskDomain()
			if err != nil {
				panicRed(err)
			}

			fmt.Println(domain)

			ips, err := internal.GetRecord(domain.Name)
			if err != nil {
				panicRed(err)
			}
			fmt.Println(ips)

			for {
				internal.Validate(ips, domain.Name)
			}

		},
	}
)

func init() {
	rootCmd.AddCommand(checkCommand)
}
