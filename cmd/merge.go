package cmd

import (
	"encoding/pem"
	"os"
	"strings"

	"github.com/ghdwlsgur/cert-check/internal"
	"github.com/spf13/cobra"
)

var (
	mergeCommand = &cobra.Command{
		Use:   "merge",
		Short: "",
		Long:  "",
		Run: func(_ *cobra.Command, _ []string) {

			certFile, err = internal.Dir()
			if err != nil {
				panicRed(err)
			}

			selectList, err := internal.AskMultiSelect("Select Certificate File", certFile.Name)
			if err != nil {
				panicRed(err)
			}

			t, err := os.Create("test.pem")
			if err != nil {
				panicRed(err)
			}
			defer t.Close()

			var k = [3]*pem.Block{}

			for _, s := range selectList {

				l := strings.Split(s, ".")
				certFile.Extension = strings.Split(s, ".")[len(l)-1]

				p, err = internal.GetPemType(s)
				if err != nil {
					panicRed(err)
				}

				if p.Type == "CERTIFICATE" {

					detail, err := internal.DistinguishCertificate(p, certFile)
					if err != nil {
						panicRed(err)
					}

					if detail == "Leaf Certificate" {
						k[0] = p.Block
					} else if detail == "Intermediate Certificate" {
						k[1] = p.Block
					} else if detail == "Root Certificate" {
						k[2] = p.Block
					}
				}
			}

			for _, v := range k {
				if err := pem.Encode(t, v); err != nil {
					panicRed(err)
				}
			}

		},
	}
)

func init() {
	rootCmd.AddCommand(mergeCommand)
}
