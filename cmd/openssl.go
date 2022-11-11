package cmd

import (
	"crypto/x509"
	"fmt"
	"os"

	"github.com/ghdwlsgur/cert-check/internal"
	"github.com/spf13/cobra"
)

var (
	certFile *internal.CertFile
)

var (
	opensslCommand = &cobra.Command{
		Use:   "openssl",
		Short: "test",
		Long:  "test",
		Run: func(_ *cobra.Command, _ []string) {

			certFile, err = internal.Dir()
			if err != nil {
				panicRed(err)
			}

			fileName, err := internal.AskCertFile(certFile.Name)
			if err != nil {
				panicRed(err)
			}

			fmt.Println(fileName)

			// regex := regexp.MustCompile("(\n)?-----(.)*-----\n")
			data, _ := os.ReadFile(fileName)
			// parts := regex.ReplaceAllString(string(data), "")
			fmt.Println(string(data))

			s, err := x509.ParseCertificate(data)
			if err != nil {
				panicRed(err)
			}

			fmt.Println(s)

		},
	}
)

func init() {
	rootCmd.AddCommand(opensslCommand)
}
