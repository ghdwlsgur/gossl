package cmd

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"strings"

	"github.com/fatih/color"
	"github.com/ghdwlsgur/cert-check/internal"
	"github.com/spf13/cobra"
)

var (
	// Query certificate or key file type and Md5 hash
	echoCommand = &cobra.Command{
		Use:   "echo",
		Short: "Show the contents of the certificate file/type and compare hashes.",
		Long:  "Show the contents of the certificate file/type and compare hashes.",
		Run: func(cmd *cobra.Command, args []string) {
			var (
				certFile *internal.CertFile
				p        *internal.Pem
				m        *internal.Md5
			)

			// Outputs a list of files with extensions ending in pem, crt, or key
			certFile, err = internal.Dir()
			if err != nil {
				panicRed(err)
			}

			// The user selects one of the list of certificates.
			fileName, err := internal.AskSelect("Select Certificate File", certFile.Name)
			if err != nil {
				panicRed(err)
			}

			// Save the extension of the selected certificate file
			internal.SetCertExtension(certFile, fileName)

			// Certificate type lookup
			p, err = internal.GetPemType(fileName)
			if err != nil {
				panicRed(err)
			}

			// Certificate file output (cat **.pem / **.crt / **.key)
			if err := pem.Encode(os.Stdout, p.Block); err != nil {
				panicRed(err)
			}

			if p.Type == "RSA PRIVATE KEY" {

				fmt.Printf("Type:   \t%s\n", color.HiRedString(p.Type))
				m, err = internal.GetMd5FromRsaPrivateKey(p)
				if err != nil {
					panicRed(err)
				}
				fmt.Printf("Md5 Hash: \t%s\n", color.HiBlackString((m.RsaPrivateKey)))

			} else if p.Type == "CERTIFICATE" {

				cert, err := x509.ParseCertificate(p.Block.Bytes)
				if err != nil {
					panicRed(err)
				}

				h := fmt.Sprintf("%s", cert.VerifyHostname(""))
				hl := strings.Split(h, ",")

				fmt.Printf("VerifyHostName: %s\n", hl[:len(hl)-1])
				fmt.Printf("Subject:\t%s\n", cert.Subject)
				fmt.Printf("Issuer Name:\t%s\n", cert.Issuer)
				fmt.Printf("Expire Date:\t%s\n", cert.NotAfter.Format("2006-January-02"))

				fmt.Printf("Type:   \t%s\n", p.Type)

				// In the case of a certificate file, classification of certificate types
				detail, err := internal.DistinguishCertificate(p, certFile)
				if err != nil {
					panicRed(err)
				}
				fmt.Printf("Detail: \t%s\n", color.HiMagentaString(detail))

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
	rootCmd.AddCommand(echoCommand)
}
