package cmd

import (
	"fmt"
	"strings"

	"github.com/ghdwlsgur/gossl/internal"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	validateCommand = &cobra.Command{
		Use:   "validate",
		Short: "Proxy the A record ip address of the cache server to review the application of the certificate.",
		Long:  "Proxy the A record ip address of the cache server to review the application of the certificate.",
		Run: func(_ *cobra.Command, _ []string) {
			var (
				err error
			)

			domain := strings.TrimSpace(viper.GetString("origin-domain"))
			if domain == "" {
				panicRed(fmt.Errorf("please enter your domain. ex) gossl connect -n naver.com"))
			}

			target := strings.TrimSpace(viper.GetString("target-domain"))
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
	validateCommand.Flags().StringP("name", "n", "", "[required] Enter the origin domain that is used as a proxy server.")
	validateCommand.Flags().StringP("target", "t", "", "[optional] The domain that sends the final response through the proxy.")

	viper.BindPFlag("origin-domain", validateCommand.Flags().Lookup("name"))
	viper.BindPFlag("target-domain", validateCommand.Flags().Lookup("target"))

	rootCmd.AddCommand(validateCommand)
}