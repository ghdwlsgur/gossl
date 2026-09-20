package cmd

import (
	"archive/zip"
	"fmt"
	"os"
	"strings"

	"github.com/fatih/color"
	"github.com/ghdwlsgur/gossl/internal"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	zipCommand = &cobra.Command{
		Use:   "zip",
		Short: "Compress each file",
		Long:  "Compress each file",
		RunE: func(_ *cobra.Command, _ []string) error {
			var (
				certFile *internal.CertFile
				err      error
			)

			argName := viper.GetString("zip-file-name")
			if argName == "" {
				argName = "gossl_zip_output"
			}
			newFile := fmt.Sprintf("%s.zip", strings.TrimSpace(argName))

			certFile, err = internal.DirGrepX509()
			if err != nil {
				return panicRed(err)
			}

			selectList, err := internal.AskMultiSelect("Choose the files to compress", certFile.Name)
			if err != nil {
				return panicRed(err)
			}

			flags := os.O_WRONLY | os.O_CREATE | os.O_TRUNC
			file, err := os.OpenFile(newFile, flags, 0644)
			if err != nil {
				return panicRed(err)
			}
			zipw := zip.NewWriter(file)
			defer zipw.Close()

			if len(selectList) > 0 {
				for _, filename := range selectList {
					if err := internal.AppendFile(filename, zipw); err != nil {
						return panicRed(err)
					}
				}
				fmt.Printf(color.HiGreenString("📄 %s created successfully\n"), newFile)
			}
			return nil
		},
	}
)

func init() {
	zipCommand.Flags().StringP("name", "n", "", "[optional] Enter the name of the compressed file.")
	viper.BindPFlag("zip-file-name", zipCommand.Flags().Lookup("name"))

	rootCmd.AddCommand(zipCommand)
}
