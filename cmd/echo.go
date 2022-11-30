package cmd

import (
	"crypto/x509"
	"fmt"
	"os"
	"strings"

	"github.com/fatih/color"
	"github.com/ghdwlsgur/gossl/internal"
	"github.com/spf13/cobra"
)

var (
	// Query certificate or key file type and Md5 hash
	echoCommand = &cobra.Command{
		Use:   "echo",
		Short: "Show the contents of the certificate file/type and compare hashes.",
		Long:  "Show the contents of the certificate file/type and compare hashes.",
		Run: func(_ *cobra.Command, _ []string) {
			var (
				certFile *internal.CertFile
				p        *internal.Pem
				m        *internal.Md5
				err      error
			)

			// Outputs a list of files with extensions ending in pem, crt, or key
			certFile, err = internal.DirGrepX509()
			if err != nil {
				panicRed(err)
			}

			// The user selects one of the list of certificates.
			fileName, err := internal.AskSelect("Select Certificate File", certFile.Name)
			if err != nil {
				panicRed(err)
			}

			data, err := os.ReadFile(fileName)
			if err != nil {
				panicRed(err)
			}

			pemBlockCount := internal.CountPemBlock(data)

			// Save the extension of the selected certificate file
			internal.SetCertExtension(certFile, fileName)

			// Certificate type lookup
			p, err = internal.GetPemType(fileName)
			if err != nil {
				panicRed(err)
			}

			// Certificate file output (cat **.pem / **.crt / **.key)
			// if err := pem.Encode(os.Stdout, p.Block); err != nil {
			// 	panicRed(err)
			// }

			fmt.Printf(color.HiWhiteString("\n%s\n"), fileName)
			if p.Type == "RSA PRIVATE KEY" {

				internal.PrintFunc("Type", color.HiRedString(p.Type))
				m, err = internal.GetMd5FromRsaPrivateKey(p)
				if err != nil {
					panicRed(err)
				}
				internal.PrintFunc("Md5 Hash", color.HiBlackString(m.RsaPrivateKey))

			} else if p.Type == "CERTIFICATE" {

				cert, err := x509.ParseCertificate(p.Block.Bytes)
				if err != nil {
					panicRed(err)
				}

				h := fmt.Sprintf("%s", cert.VerifyHostname(""))
				hl := strings.Split(h, ",")

				fmt.Printf("%s\t%s\n",
					color.HiBlackString("Verify Host"),
					strings.TrimSpace(strings.Split(hl[:len(hl)-1][0], ":")[1]))
				internal.PrintSplitFunc("Subject", cert.Subject.String())
				internal.PrintSplitFunc("Issuer Name", cert.Issuer.String())
				internal.PrintFunc("Expire Date", cert.NotAfter.Format("2006-January-02"))
				internal.PrintFunc("Type", p.Type)

				detail, err := internal.DistinguishCertificate(p, certFile, pemBlockCount)
				if err != nil {
					panicRed(err)
				}
				internal.PrintFunc("Detail", color.MagentaString(detail))

				m, err = internal.GetMd5FromCertificate(p)
				if err != nil {
					panicRed(err)
				}
				internal.PrintFunc("Md5 Hash", color.HiBlackString(m.Certificate))
			}
			fmt.Println()
		},
	}
)

func init() {
	rootCmd.AddCommand(echoCommand)
}

// ephemeral
// func whois(domainName, server string) string {
// 	conn, err := net.Dial("tcp", server+":43")
// 	if err != nil {
// 		fmt.Println("Error")
// 	}

// 	defer conn.Close()

// 	conn.Write([]byte(domainName + "\r\n"))

// 	buf := make([]byte, 1024)
// 	result := []byte{}

// 	for {
// 		numBytes, err := conn.Read(buf)
// 		fmt.Println(numBytes)
// 		sbuf := buf[0:numBytes]
// 		result = append(result, sbuf...)
// 		if err != nil {
// 			break
// 		}
// 	}

// 	return string(result)
// }
