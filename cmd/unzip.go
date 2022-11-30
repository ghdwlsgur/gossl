package cmd

import (
	"strings"

	"github.com/ghdwlsgur/gossl/internal"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	unzipCommand = &cobra.Command{
		Use:   "unzip",
		Short: "Unzip the zip file extension.",
		Long:  "Unzip the zip file extension.",
		Run: func(_ *cobra.Command, _ []string) {
			var (
				zipFile *internal.ZipFile
				err     error
			)

			zipFile, err = internal.DirGrepZip()
			if err != nil {
				panicRed(err)
			}

			fileName, err := internal.AskSelect("Select Zip File", zipFile.Name)
			if err != nil {
				panicRed(err)
			}

			newFileName := viper.GetString("unzip-file-name")
			if newFileName == "" {
				newFileName = strings.Split(fileName, ".")[0]
			}

			err = internal.UnZip(fileName, newFileName)
			if err != nil {
				panicRed(err)
			}
		},
	}
)

func init() {
	unzipCommand.Flags().StringP("name", "n", "", "[optional] Enter the name of the uncompressed file.")

	viper.BindPFlag("unzip-file-name", unzipCommand.Flags().Lookup("name"))

	rootCmd.AddCommand(unzipCommand)
}
