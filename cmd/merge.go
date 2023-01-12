package cmd

import (
	"encoding/pem"
	"fmt"
	"os"
	"strings"

	"github.com/fatih/color"
	"github.com/ghdwlsgur/gossl/internal"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	mergeCommand = &cobra.Command{
		Use:   "merge",
		Short: "Combine each certificate file in order of leaf, intermediate, root.",
		Long:  "Combine each certificate file in order of leaf, intermediate, root.",
		Run: func(_ *cobra.Command, _ []string) {
			var (
				certFile *internal.CertFile
				p        *internal.Pem
				err      error
			)

			argName := viper.GetString("pem-file-name")
			if argName == "" {
				argName = "gossl_merge_output"
			}
			newFile := fmt.Sprintf("%s.pem", strings.TrimSpace(argName))

			certFile, err = internal.DirGrepX509()
			if err != nil {
				panicRed(err)
			}

			selectList, err := internal.AskMultiSelect("Select Certificate File", certFile.Name)
			if err != nil {
				panicRed(err)
			}

			n := len(selectList)
			if n > 4 {
				panicRed(fmt.Errorf("please select up to 4"))
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
			privateBlock := []*pem.Block{}

			flagF := viper.GetBool("add-private-key")

			for _, selectCert := range selectList {
				internal.SetCertExtension(certFile, selectCert)

				data, err := os.ReadFile(selectCert)
				if err != nil {
					panicRed(err)
				}

				if !flagF {
					b, _ := pem.Decode(data)
					if b.Type == "RSA PRIVATE KEY" {
						panicRed(fmt.Errorf("please select only the certificate file"))
					}
				} else {
					b, _ := pem.Decode(data)
					if b.Type == "RSA PRIVATE KEY" {
						privateBlock = append(privateBlock, b)
					}
				}

				p, err = internal.GetPemType(selectCert)
				if err != nil {
					panicRed(err)
				}

				pemBlockCount := internal.CountPemBlock(data)

				if p.Type != "RSA PRIVATE KEY" {
					detail, err := internal.DistinguishCertificate(p, certFile, pemBlockCount)
					if err != nil {
						panicRed(err)
					}

					typeOfCertificate := strings.TrimSpace(strings.Split(detail, " ")[0])
					if typeOfCertificate == "Unified" {
						panicRed(fmt.Errorf("%s is already merged certificate file, please choose another file", selectCert))
					}

					for {
						var block *pem.Block
						block, data = pem.Decode(data)
						if block == nil {
							break
						}

						if typeOfCertificate == "Leaf" {
							leafBlock = append(leafBlock, block)
						} else if typeOfCertificate == "Intermediate" {
							intermediateBlock = append(intermediateBlock, block)
						} else if typeOfCertificate == "Root" {
							rootBlock = append(rootBlock, block)
						}

						if len(data) == 0 {
							break
						}
					}
				}
			}

			blockBucket := make([][]*pem.Block, 4)
			blockBucket[0] = leafBlock
			blockBucket[1] = intermediateBlock
			blockBucket[2] = rootBlock
			blockBucket[3] = privateBlock

			for i := 0; i < len(blockBucket); i++ {
				for _, block := range blockBucket[i] {
					if err := pem.Encode(file, block); err != nil {
						panicRed(err)
					}
				}
			}
			fmt.Printf(color.HiGreenString("📄 %s created successfully\n"), newFile)
		},
	}
)

func init() {
	mergeCommand.Flags().StringP("name", "n", "", "[optional] Enter the file name to create.")
	mergeCommand.Flags().BoolP("force", "f", false, "[optional] merge key file and certificate file")

	viper.BindPFlag("pem-file-name", mergeCommand.Flags().Lookup("name"))
	viper.BindPFlag("add-private-key", mergeCommand.Flags().Lookup("force"))

	rootCmd.AddCommand(mergeCommand)
}
