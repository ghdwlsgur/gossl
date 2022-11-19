package cmd

import (
	"archive/zip"
	"fmt"
	"os"
	"strings"

	"github.com/ghdwlsgur/gossl/internal"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	zipCommand = &cobra.Command{
		Use:   "zip",
		Short: "Compress each file",
		Long:  "Compress each file",
		Run: func(_ *cobra.Command, _ []string) {
			var (
				certFile *internal.CertFile
			)

			argName := viper.GetString("zip-file-name")
			if argName == "" {
				argName = "gossl_zip_output"
			}
			newFile := fmt.Sprintf("%s.zip", strings.TrimSpace(argName))

			certFile, err = internal.Dir()
			if err != nil {
				panicRed(err)
			}

			selectList, err := internal.AskMultiSelect("Choose the files to compress", certFile.Name)
			if err != nil {
				panicRed(err)
			}

			flags := os.O_WRONLY | os.O_CREATE | os.O_TRUNC
			file, err := os.OpenFile(newFile, flags, 0644)
			if err != nil {
				panicRed(err)
			}

			zipw := zip.NewWriter(file)
			defer zipw.Close()

			for _, filename := range selectList {
				if err := internal.AppendFile(filename, zipw); err != nil {
					panicRed(err)
				}
			}

		},
	}
)

func init() {
	zipCommand.Flags().StringP("name", "n", "", "[optional] Enter the name of the compressed file.")

	viper.BindPFlag("zip-file-name", zipCommand.Flags().Lookup("name"))

	rootCmd.AddCommand(zipCommand)
}
