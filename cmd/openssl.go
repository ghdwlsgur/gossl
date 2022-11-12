package cmd

import (
	"fmt"

	"github.com/ghdwlsgur/cert-check/internal"
	"github.com/spf13/cobra"
)

var (
	certFile *internal.CertFile
	p        *internal.Pem
	m        *internal.Md5
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

			p, err = internal.GetPemType(fileName)
			if err != nil {
				panicRed(err)
			}

			if p.Type == "RSA PRIVATE KEY" {

				m, err = internal.GetMd5FromRsaPrivateKey(p, "speedy0620#@1")
				if err != nil {
					panicRed(err)
				}
				fmt.Println(m.RsaPrivateKey)

			} else if p.Type == "CERTIFICATE" {

				m, err = internal.GetMd5FromCertificate(p)
				if err != nil {
					panicRed(err)
				}
				fmt.Println(m.Certificate)

			}

		},
	}
)

func init() {
	rootCmd.AddCommand(opensslCommand)
}
