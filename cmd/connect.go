package cmd

import (
	"fmt"
	"strings"

	"github.com/ghdwlsgur/gossl/internal"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	connectCommand = &cobra.Command{
		Use:   "connect",
		Short: "Connect to the target domain from the origin domain's name server.",
		Long:  "Connect to the target domain from the origin domain's name server.",
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
	connectCommand.Flags().StringP("name", "n", "", "[required] Enter the origin domain that is used as a proxy server.")
	connectCommand.Flags().StringP("target", "t", "", "[optional] The domain that sends the final response through the proxy.")

	viper.BindPFlag("origin-domain", connectCommand.Flags().Lookup("name"))
	viper.BindPFlag("target-domain", connectCommand.Flags().Lookup("target"))

	rootCmd.AddCommand(connectCommand)
}
