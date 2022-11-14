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
	md5Command = &cobra.Command{
		Use:   "md5",
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

			fmt.Printf("Type: %s\n", p.Type)
			if p.Type == "RSA PRIVATE KEY" {

				m, err = internal.GetMd5FromRsaPrivateKey(p)
				if err != nil {
					panicRed(err)
				}
				fmt.Printf("Md5 Hash: %s\n", m.RsaPrivateKey)

			} else if p.Type == "CERTIFICATE" {

				m, err = internal.GetMd5FromCertificate(p)
				if err != nil {
					panicRed(err)
				}
				fmt.Printf("Md5 Hash: %s\n", m.Certificate)

			}

		},
	}
)

func init() {
	rootCmd.AddCommand(md5Command)
}
