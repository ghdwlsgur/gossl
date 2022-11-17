package cmd

import (
	"encoding/pem"
	"fmt"
	"os"

	"github.com/ghdwlsgur/cert-check/internal"
	"github.com/spf13/cobra"
)

var (
	mergeCommand = &cobra.Command{
		Use:   "merge",
		Short: "",
		Long:  "",
		Run: func(_ *cobra.Command, _ []string) {

			arg, err := internal.GetArguments(os.Args)
			if err != nil {
				panicRed(err)
			}
			newFile := fmt.Sprintf("%s.pem", arg)

			certFile, err = internal.Dir()
			if err != nil {
				panicRed(err)
			}

			selectList, err := internal.AskMultiSelect("Select Certificate File", certFile.Name)
			if err != nil {
				panicRed(err)
			}

			n := len(selectList)
			if n > 3 {
				panicRed(fmt.Errorf("please select up to 3"))
			}

			// if n < 2 {
			// 	panicRed(fmt.Errorf("please select at least 2"))
			// }

			// if n == 2 {
			// 	n += 1
			// }

			t, err := os.Create(newFile)
			if err != nil {
				panicRed(err)
			}
			defer t.Close()

			// k := make([]*pem.Block, n)

			for _, s := range selectList {
				internal.SetCertExtension(certFile, s)

				p, err = internal.GetPemType(s)
				// if err != nil {
				// 	panicRed(err)
				// }

				data, err := os.ReadFile(s)
				if err != nil {
					panicRed(err)
				}
				var blocks []byte
				p = &internal.Pem{}
				for {
					var block *pem.Block
					block, data = pem.Decode(data)
					if block == nil {
						break
					}
					if err := pem.Encode(t, block); err != nil {
						panicRed(err)
					}
					blocks = append(blocks, block.Bytes...)
					if len(data) == 0 {
						break
					}
				}

				// c, err := x509.ParseCertificates(blocks)
				// if err != nil {
				// 	panicRed(err)
				// }
				// for _, asd := range c {
				// 	fmt.Println(asd.PublicKey.(*rsa.PublicKey).N)
				// }

				// p, _ := pem.Decode(data)

				// if err := pem.Encode(os.Stdout, p.Block); err != nil {
				// 	panicRed(err)
				// }

				// 	if p.Type == "CERTIFICATE" {
				// 		detail, err := internal.DistinguishCertificate(p, certFile)
				// 		if err != nil {
				// 			panicRed(err)
				// 		}

				// 		if detail == "Leaf Certificate" {
				// 			k[0] = p.Block
				// 		} else if detail == "Intermediate Certificate" {
				// 			k[1] = p.Block
				// 			// fmt.Println(base64.StdEncoding.EncodeToString(p.Block.Bytes))
				// 		} else if detail == "Root Certificate" {
				// 			k[2] = p.Block
				// 		}
				// 	} else {
				// 		panicRed(fmt.Errorf("please select only the certificate file"))
				// 	}
				// }

				// var blocks []byte
				// for _, v := range k {
				// 	// fmt.Println("g")
				// 	// rest := v.Bytes
				// 	// for {
				// 	// 	var block *pem.Block
				// 	// 	block, rest := pem.Decode(rest)
				// 	// 	if block == nil {
				// 	// 		fmt.Println("go")
				// 	// 		break
				// 	// 	}
				// 	// 	blocks = append(blocks, block.Bytes...)
				// 	// 	if len(rest) == 0 {
				// 	// 		break
				// 	// 	}
				// 	// 	if err := pem.Encode(os.Stdout, block); err != nil {
				// 	// 		panicRed(err)
				// 	// 	}
				// 	// }

				// 	if err := pem.Encode(t, v); err != nil {
				// 		panicRed(err)
				// 	}

				// 	// if err := pem.Encode(os.Stdout, b); err != nil {
				// 	// 	panicRed(err)
				// 	// }

			}

		},
	}
)

func init() {
	rootCmd.AddCommand(mergeCommand)
}
