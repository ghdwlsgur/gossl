package cmd

import (
	"path/filepath"
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
		RunE: func(_ *cobra.Command, _ []string) error {
			return runUnzip(viper.GetString("unzip-file-name"))
		},
	}
)

// unzipTarget 은 압축을 풀 디렉토리 이름을 정한다.
// 지정하지 않으면 확장자를 뗀 파일명을 쓴다.
func unzipTarget(zipName, requested string) string {
	if requested != "" {
		return requested
	}
	return strings.TrimSuffix(zipName, filepath.Ext(zipName))
}

// runUnzip 은 현재 디렉토리의 zip 하나를 골라 푼다.
func runUnzip(requestedName string) error {
	zipFile, err := internal.DirGrepZip()
	if err != nil {
		return panicRed(err)
	}

	fileName, err := internal.AskSelect("Select Zip File", zipFile.Name)
	if err != nil {
		return panicRed(err)
	}

	if err := internal.UnZip(fileName, unzipTarget(fileName, requestedName)); err != nil {
		return panicRed(err)
	}
	return nil
}

func init() {
	unzipCommand.Flags().StringP("name", "n", "", "[optional] Enter the name of the uncompressed file.")

	viper.BindPFlag("unzip-file-name", unzipCommand.Flags().Lookup("name"))

	rootCmd.AddCommand(unzipCommand)
}
