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

func saveFile(b []*pem.Block, typeName string, blockCount int) error {

	for blockCount >= 1 {
		err := saveFileAsType(b, typeName, blockCount)
		if err != nil {
			return err
		}
		blockCount--
	}
	return nil
}

func saveFileAsType(b []*pem.Block, typeName string, blockCount int) error {

	fileName := fmt.Sprintf("gossl_%s_%d.crt", typeName, blockCount)
	if len(b) > 0 {
		newFile, err := createFile(fileName)
		if err != nil {
			return err
		}
		if err := pem.Encode(newFile, b[blockCount-1]); err != nil {
			return err
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
		Run: func(cmd *cobra.Command, args []string) {
			var (
				certFile               *internal.CertFile
				p                      *internal.Pem
				err                    error
				selectList             []string
				pemBlockCount          int
				leafBlockCount         int
				intermediateBlockCount int
				rootBlockCount         int
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

			fmt.Printf("✅ %s\n", color.HiGreenString(file))

			leafSubIss := []string{}
			intermediateSubIss := []string{}
			rootSubIss := []string{}
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
					subIss, err := internal.GetSubjectCNandIssuerCN(block)
					if err != nil {
						panicRed(err)
					}
					leafSubIss = append(leafSubIss, subIss...)
					leafBlockCount++
				case "Intermediate":
					intermediateBlock = append(intermediateBlock, block)
					subIss, err := internal.GetSubjectCNandIssuerCN(block)
					if err != nil {
						panicRed(err)
					}
					intermediateSubIss = append(intermediateSubIss, subIss...)
					intermediateBlockCount++
				case "Root":
					rootBlock = append(rootBlock, block)
					subIss, err := internal.GetSubjectCNandIssuerCN(block)
					if err != nil {
						panicRed(err)
					}
					rootSubIss = append(rootSubIss, subIss...)
					rootBlockCount++
				}

				if len(data) == 0 {
					break
				}
			}

			if len(args) > 0 && args[0] == "show" {
				if len(leafSubIss) > 0 && len(intermediateSubIss) > 0 {
					if leafSubIss[len(leafSubIss)-1] == intermediateSubIss[0] {
						fmt.Printf("\n%s %s\n", color.HiBlackString("Leaf:[Issuer CN] Intermediate:[Subject CN]"), color.HiMagentaString("Matched"))
					} else {
						fmt.Printf("\n%s %s\n", color.HiBlackString("Leaf:[Issuer CN] Intermediate:[Subject CN]"), color.HiRedString("Not Matched"))
					}
				}

				if len(intermediateSubIss) > 0 && len(rootSubIss) > 0 {
					if intermediateSubIss[len(intermediateSubIss)-1] == rootSubIss[0] {
						fmt.Printf("%s %s\n", color.HiBlackString("Intermediate:[Issuer CN] Root:[Subject CN]"), color.HiMagentaString("Matched"))
					} else {
						fmt.Printf("%s %s\n", color.HiBlackString("Intermediate:[Issuer CN] Root:[Subject CN]"), color.HiRedString("Not Matched"))
					}
				}
			}

			if len(args) < 1 {
				fmt.Printf("\n%s\n", color.HiWhiteString("Created Files"))
				if saveFile(leafBlock, "leaf", leafBlockCount); err != nil {
					panicRed(err)
				}
				if saveFile(intermediateBlock, "intermediate", intermediateBlockCount); err != nil {
					panicRed(err)
				}
				if saveFile(rootBlock, "root", rootBlockCount); err != nil {
					panicRed(err)
				}
			}
		},
	}
)

func init() {
	rootCmd.AddCommand(splitCommand)
}
