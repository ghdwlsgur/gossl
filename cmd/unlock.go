package cmd

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/ghdwlsgur/gossl/internal"
	"github.com/spf13/cobra"
)

var (
	unlockCommand = &cobra.Command{
		Use:   "unlock",
		Short: "Unlock RSA PRIVATE KEY FILE",
		Long:  "Unlock RSA PRIVATE KEY FILE",
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

			fileName, err := internal.AskSelect("Select RSA PRIVATE KEY File", certFile.Name)
			if err != nil {
				panicRed(err)
			}

			p, err = internal.GetPemType(fileName)
			if err != nil {
				panicRed(err)
			}

			if p.Type != "RSA PRIVATE KEY" {
				panicRed(fmt.Errorf("select only rsa private key file please"))
			}

			block := p.Block
			isEncrypted := x509.IsEncryptedPEMBlock(block)

			fmt.Println("check4")
			if isEncrypted {
				password, err := internal.AskInput("What is your password", 1)
				if err != nil {
					panicRed(err)
				}

				b, err := x509.DecryptPEMBlock(block, []byte(password))
				if err != nil {
					panicRed(err)
				}

				existfile, err := os.Create(fileName)
				if err != nil {
					panicRed(err)
				}
				defer existfile.Close()

				if pem.Encode(existfile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: b}); err != nil {
					panicRed(err)
				}

			} else {
				panicRed(fmt.Errorf("this rsa private key file is not locked"))
			}
		},
	}
)

func init() {
	rootCmd.AddCommand(unlockCommand)
}
