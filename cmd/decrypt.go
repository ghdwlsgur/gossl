package cmd

import (
	"crypto/x509"
	"fmt"
	"strings"

	"github.com/fatih/color"
	"github.com/ghdwlsgur/cert-check/internal"
	"github.com/spf13/cobra"
)

var (
	certFile *internal.CertFile
	p        *internal.Pem
	m        *internal.Md5
)

var (
	decryptCommand = &cobra.Command{
		Use:   "decrypt",
		Short: "test",
		Long:  "test",
		Run: func(_ *cobra.Command, _ []string) {

			certFile, err = internal.Dir()
			if err != nil {
				panicRed(err)
			}

			fileName, err := internal.AskSelect("Choose pem file", certFile.Name, len(certFile.Name))
			if err != nil {
				panicRed(err)
			}

			fmt.Println(fileName)

			l := strings.Split(fileName, ".")
			certFile.Extension = strings.Split(fileName, ".")[len(l)-1]

			p, err = internal.GetPemType(fileName)
			if err != nil {
				panicRed(err)
			}

			if p.Type == "CERTIFICATE" {
				fmt.Printf("Type:   \t%s\n", p.Type)
			} else {
				fmt.Printf("Type:   \t%s\n", color.HiRedString(p.Type))
			}

			if p.Type == "RSA PRIVATE KEY" {

				m, err = internal.GetMd5FromRsaPrivateKey(p)
				if err != nil {
					panicRed(err)
				}
				fmt.Printf("Md5 Hash: \t%s\n", color.HiBlackString((m.RsaPrivateKey)))

			} else if p.Type == "CERTIFICATE" {

				t, err := x509.ParseCertificate(p.Block.Bytes)
				if err != nil {
					panicRed(err)
				}

				if t.IsCA {
					if t.Subject.String() == t.Issuer.String() {
						fmt.Printf("Detail: \t%s\n", color.HiMagentaString(("Root Certificate")))
					} else {
						fmt.Printf("Detail: \t%s\n", "Intermediate Certificate")
					}
				} else {
					if certFile.Extension == "crt" {
						fmt.Printf("Detail: \t%s\n", "Leaf Certificate")
					}
				}

				m, err = internal.GetMd5FromCertificate(p)
				if err != nil {
					panicRed(err)
				}
				fmt.Printf("Md5 Hash: \t%s\n", color.HiBlackString(m.Certificate))
			}

		},
	}
)

func init() {
	rootCmd.AddCommand(decryptCommand)
}
