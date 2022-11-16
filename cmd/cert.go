package cmd

import (
	"fmt"
	"os"

	"github.com/ghdwlsgur/cert-check/internal"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	err error
)

func getArguments(arg []string) (string, error) {

	if len(arg) < 3 {
		return "", fmt.Errorf("please write the domain as an argument")
	}
	return arg[2:3][0], nil
}

var (
	certCommand = &cobra.Command{
		Use:   "cert",
		Short: "test",
		Long:  "test",
		Run: func(_ *cobra.Command, _ []string) {

			domain, err := getArguments(os.Args)
			if err != nil {
				panicRed(err)
			}

			var target string
			target = viper.GetString("target-domain")

			if target == "" {
				target = domain
			}

			ips, err := internal.GetRecord(domain)
			if err != nil {
				panicRed(err)
			}

			for {
				_, err = internal.GetCertificateOnTheProxy(ips, domain, target)
				if err != nil {
					panicRed(err)
				}
			}
		},
	}
)

func init() {
	certCommand.Flags().StringP("t", "", "", "description")
	viper.BindPFlag("target-domain", certCommand.Flags().Lookup("t"))

	rootCmd.AddCommand(certCommand)
}
