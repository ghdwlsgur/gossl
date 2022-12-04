package cmd

import (
	"encoding/pem"
	"fmt"
	"os"
	"strings"

	"github.com/fatih/color"
	"github.com/ghdwlsgur/gossl/internal"
	"github.com/spf13/cobra"
)

func createFile(fileName string) (*os.File, error) {
	file, err := os.Create(fileName)
	if err != nil {
		return nil, err
	}
	return file, nil
}

func saveFileAsType(b []*pem.Block, typeName string) error {

	fileName := fmt.Sprintf("gossl_%s.crt", typeName)
	if len(b) > 0 {
		newFile, err := createFile(fileName)
		if err != nil {
			return err
		}
		for _, block := range b {
			if err := pem.Encode(newFile, block); err != nil {
				return err
			}
		}
		fmt.Printf("📄 %s %s\n", color.HiGreenString(fileName), "created successfully")
	}
	return nil
}

var (
	splitCommand = &cobra.Command{
		Use:   "split",
		Short: "Split Unified Certificate.",
		Long:  "Split Unified Certificate.",
		Run: func(_ *cobra.Command, args []string) {
			var (
				certFile      *internal.CertFile
				p             *internal.Pem
				err           error
				selectList    []string
				pemBlockCount int
			)

			if len(args) > 0 {
				if args[0] != "show" || len(args) > 1 {
					panicRed(fmt.Errorf("input format is incorrect. ex) gossl split show"))
				}
			}

			certFile, err = internal.DirGrepX509()
			if err != nil {
				panicRed(err)
			}

			for _, certificateFileName := range certFile.Name {
				data, err := os.ReadFile(certificateFileName)
				if err != nil {
					panicRed(err)
				}

				pemBlockCount = internal.CountPemBlock(data)
				if pemBlockCount > 1 {
					name := fmt.Sprintf("%s [in %d Block]", certificateFileName, pemBlockCount)
					selectList = append(selectList, name)
					certFile.Name = append(certFile.Name, certificateFileName)
				}
			}

			if len(selectList) < 1 {
				panicRed(fmt.Errorf("a certificate file with pem block length greater than 2 does not exist"))
			}

			selectFile, err := internal.AskSelect("Select Certificate File", selectList)
			if err != nil {
				panicRed(err)
			}

			file := strings.TrimSpace(strings.Split(selectFile, "[")[0])

			certFile.Name = selectList
			internal.SetCertExtension(certFile, file)

			data, err := os.ReadFile(file)
			if err != nil {
				panicRed(err)
			}

			p, err = internal.GetPemType(file)
			if err != nil {
				panicRed(err)
			}

			leafBlock := []*pem.Block{}
			intermediateBlock := []*pem.Block{}
			rootBlock := []*pem.Block{}

			fmt.Printf("%s\n", color.HiWhiteString("Certificate Type"))
			fmt.Printf("✅ %s\n", file)
			for {
				var block *pem.Block
				block, data = pem.Decode(data)
				if block == nil {
					break
				}

				p.Block = block
				detail, err := internal.DistinguishCertificate(p, certFile, 1)
				if err != nil {
					panicRed(err)
				}

				fmt.Printf("\t ➕ %s\n", color.HiWhiteString(detail))

				switch strings.TrimSpace(strings.Split(detail, " ")[0]) {
				case "Leaf":
					leafBlock = append(leafBlock, block)
				case "Intermediate":
					intermediateBlock = append(intermediateBlock, block)
				case "Root":
					rootBlock = append(rootBlock, block)
				}

				if len(data) == 0 {
					break
				}
			}

			if len(args) < 1 {
				fmt.Printf("\n%s\n", color.HiWhiteString("Created Files"))
				if saveFileAsType(leafBlock, "leaf"); err != nil {
					panicRed(err)
				}
				if saveFileAsType(intermediateBlock, "intermediate"); err != nil {
					panicRed(err)
				}
				if saveFileAsType(rootBlock, "root"); err != nil {
					panicRed(err)
				}
			}

		},
	}
)

func init() {
	rootCmd.AddCommand(splitCommand)
}
