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
	_parseCrt = func(fileName string, pem *internal.Pem) error {
		question := fmt.Sprintf("This is %s, Do you want to change to %s ?", color.HiRedString("CRT"), color.HiGreenString("CERTIFICATE"))
		answer, err := internal.AskSelect(question, []string{"Yes (Overwrite file)", "No (exit)"})
		if err != nil {
			return err
		}

		if strings.Split(answer, " ")[0] == "Yes" {
			err = internal.CrtToCertificate(fileName, pem.Data)
			if err != nil {
				panicRed(err)
			}
			fmt.Print(color.HiGreenString("✅ Converted successfully (crt -> pem)"))
		} else {
			os.Exit(1)
		}
		return nil
	}

	_parsePrivateKey = func(fileName string, pem *internal.Pem) error {
		question := fmt.Sprintf("This is %s, Do you want to change to %s ?", color.HiRedString("PRIVATE KEY"), color.HiGreenString("RSA PRIVATE KEY"))
		answer, err := internal.AskSelect(question, []string{"Yes (Overwrite file)", "No (exit)"})
		if err != nil {
			return err
		}
		if strings.Split(answer, " ")[0] == "Yes" {
			err = internal.PrivateToRsaPrivate(fileName, pem.Block)
			if err != nil {
				return err
			}
			fmt.Print(color.HiGreenString("✅ Converted successfully (PRIVATE KEY -> RSA PRIVATE KEY)"))
		} else {
			os.Exit(1)
		}
		return nil
	}

	_parseRsaPrivateKey = func(pem *internal.Pem) error {
		fmt.Println()
		internal.PrintFunc("Type", color.HiRedString(pem.Type))
		md5, err := internal.GetMd5FromRsaPrivateKey(pem)
		if err != nil {
			return err
		}
		internal.PrintFunc("Md5 Hash", color.HiBlackString(md5.RsaPrivateKey))

		return nil
	}

	_parseCertificate = func(certFile *internal.CertFile, pemBlockCount int, pem *internal.Pem) error {
		cert, err := x509.ParseCertificate(pem.Block.Bytes)
		if err != nil {
			panicRed(err)
		}

		fmt.Printf(color.HiWhiteString("\n%s\n"), strings.Split(cert.Issuer.String(), ",")[0])

		h := fmt.Sprintf("%s", cert.VerifyHostname(""))
		hl := strings.Split(h, ",")

		fmt.Printf("%s\t%s\n",
			color.HiBlackString("Verify Host"),
			strings.TrimSpace(strings.Split(hl[:len(hl)-1][0], ":")[1]))
		internal.PrintSplitFunc("Subject", cert.Subject.String())

		if len(cert.DNSNames) > 0 {
			dnsToString := strings.Join(cert.DNSNames, " ")
			fmt.Printf("%s\t%s\n",
				color.HiBlackString("SAN DNS  "),
				color.HiMagentaString(strings.ReplaceAll(dnsToString, " ", "\n\t\t")))
		}
		internal.PrintSplitFunc("Issuer Name", cert.Issuer.String())
		internal.PrintFunc("Expire Date", cert.NotAfter.Format("2006-January-02"))
		internal.PrintFunc("Type", pem.Type)

		detail, err := internal.DistinguishCertificate(pem, certFile, pemBlockCount)
		if err != nil {
			return err
		}
		internal.PrintFunc("Detail", color.HiMagentaString(detail))

		md5, err := internal.GetMd5FromCertificate(pem)
		if err != nil {
			return err
		}
		internal.PrintFunc("Md5 Hash", color.HiBlackString(md5.Certificate))

		return nil
	}
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
				err      error
			)

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

			switch p.Type {
			case "PRIVATE KEY":
				_parsePrivateKey(fileName, p)
			case "RSA PRIVATE KEY":
				_parseRsaPrivateKey(p)
			case "CERTIFICATE":
				_parseCertificate(certFile, pemBlockCount, p)
			case "CRT":
				_parseCrt(fileName, p)

			default:
				panicRed(fmt.Errorf("sorry, %s isn't supported", p.Type))
			}
			fmt.Println()
		},
	}
)

func init() {
	rootCmd.AddCommand(echoCommand)
}
