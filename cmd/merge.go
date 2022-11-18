package cmd

import (
	"encoding/pem"
	"fmt"
	"os"
	"strings"

	"github.com/ghdwlsgur/gossl/internal"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	mergeCommand = &cobra.Command{
		Use:   "merge",
		Short: "Combine each certificate file in order of leaf, intermediate, root.",
		Long:  "Combine each certificate file in order of leaf, intermediate, root.",
		Run: func(cmd *cobra.Command, args []string) {
			var (
				certFile *internal.CertFile
				p        *internal.Pem
			)

			argName := viper.GetString("file-name")
			if argName == "" {
				argName = "gossl_merge_output"
			}
			newFile := fmt.Sprintf("%s.pem", strings.TrimSpace(argName))

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

			if n < 2 {
				panicRed(fmt.Errorf("please select at least 2"))
			}

			file, err := os.Create(newFile)
			if err != nil {
				panicRed(err)
			}
			defer file.Close()

			leafBlock := []*pem.Block{}
			intermediateBlock := []*pem.Block{}
			rootBlock := []*pem.Block{}

			for _, selectCert := range selectList {
				internal.SetCertExtension(certFile, selectCert)

				p, err = internal.GetPemType(selectCert)
				if err != nil {
					panicRed(err)
				}

				detail, err := internal.DistinguishCertificate(p, certFile)
				if err != nil {
					panicRed(err)
				}

				data, err := os.ReadFile(selectCert)
				if err != nil {
					panicRed(err)
				}

				b, _ := pem.Decode(data)
				if b.Type == "RSA PRIVATE KEY" {
					panicRed(fmt.Errorf("please select only the certificate file"))
				}

				for {
					var block *pem.Block
					block, data = pem.Decode(data)
					if block == nil {
						break
					}

					if detail == "Leaf Certificate" {
						leafBlock = append(leafBlock, block)
					} else if detail == "Intermediate Certificate" {
						intermediateBlock = append(intermediateBlock, block)
					} else if detail == "Root Certificate" {
						rootBlock = append(rootBlock, block)
					}

					if len(data) == 0 {
						break
					}
				}

			}

			blockBucket := make([][]*pem.Block, 3)
			blockBucket[0] = leafBlock
			blockBucket[1] = intermediateBlock
			blockBucket[2] = rootBlock

			for i := 0; i < len(blockBucket); i++ {
				for _, block := range blockBucket[i] {
					if err := pem.Encode(file, block); err != nil {
						panicRed(err)
					}
				}
			}
		},
	}
)

func init() {
	mergeCommand.Flags().StringP("name", "n", "", "[optional] Enter the file name to create.")

	viper.BindPFlag("file-name", mergeCommand.Flags().Lookup("name"))

	rootCmd.AddCommand(mergeCommand)
}
