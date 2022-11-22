package cmd

import (
	"fmt"
	"strings"

	"github.com/ghdwlsgur/gossl/internal"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	statCommand = &cobra.Command{
		Use:   "stat",
		Short: "Exec `gossl stat http` or `gossl stat https`",
		Long:  "Receives the response of the url to each A record of the target domain to the url using the http or https protocol.",
		Run: func(_ *cobra.Command, args []string) {
			var (
				err     error
				url     string
				urlHost string
				target  string
				port    int
				host    string
				referer string
			)

			protocol := args[0]
			if len(args) > 1 {
				panicRed(fmt.Errorf("up to one argument can be entered"))
			}

			url = strings.TrimSpace(viper.GetString("url-domain"))
			if url == "" {
				panicRed(fmt.Errorf("please enter your url. ex) gossl stat -u naver.com/test/test.mp4"))
			}

			urlHost = strings.Split(url, "/")[0]
			if urlHost == "http:" {
				panicRed(fmt.Errorf("please remove the protocol specification.\n ex) http://naver.com ➡️  naver.com"))
			}

			target = strings.TrimSpace(viper.GetString("stat-target-domain"))
			if target == "" {
				panicRed(fmt.Errorf("please enter your target. ex) gossl stat -t naver.com"))
			}

			host = strings.TrimSpace(viper.GetString("host-name"))
			referer = strings.TrimSpace(viper.GetString("referer-name"))

			ips, err := internal.GetRecord(target)
			if err != nil {
				panicRed(err)
			}

			if protocol == "http" {
				port = viper.GetInt("port-number")

				for _, ip := range ips {
					err = internal.HTTPResponseStat(ip.String(), url, urlHost, target, port, host, referer)
					if err != nil {
						panicRed(err)
					}
				}
			}

			if protocol == "https" {
				for _, ip := range ips {
					err = internal.HTTPSResponseStat(ip.String(), url, urlHost, target, host, referer)
					if err != nil {
						panicRed(err)
					}
				}
			}

		},
	}
)

func init() {
	statCommand.Flags().StringP("url", "u", "", "[required] Enter the domain starting with the host header, not including http and https.")
	statCommand.Flags().StringP("target", "t", "", "[required] Receive responses by proxying the A record of the domain forwarded to the target.")
	statCommand.Flags().IntP("port", "p", 80, "[optional] For http protocol, the default value is 80.")
	statCommand.Flags().StringP("http-host", "H", "", "[optional] The host to put in the request headers.")
	statCommand.Flags().StringP("referer", "r", "", "[optional]")

	viper.BindPFlag("url-domain", statCommand.Flags().Lookup("url"))
	viper.BindPFlag("stat-target-domain", statCommand.Flags().Lookup("target"))
	viper.BindPFlag("port-number", statCommand.Flags().Lookup("port"))
	viper.BindPFlag("host-name", statCommand.Flags().Lookup("http-host"))
	viper.BindPFlag("referer-name", statCommand.Flags().Lookup("referer"))

	rootCmd.AddCommand(statCommand)
}
