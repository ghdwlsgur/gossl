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
			return runZip(viper.GetString("zip-file-name"))
		},
	}
)

func init() {
	zipCommand.Flags().StringP("name", "n", "", "[optional] Enter the name of the compressed file.")
	viper.BindPFlag("zip-file-name", zipCommand.Flags().Lookup("name"))

	rootCmd.AddCommand(zipCommand)
}

// outputName 은 사용자가 준 이름을 다듬어 확장자를 붙인다.
// 비어 있으면 기본 이름을 쓴다.
func outputName(requested, fallback, ext string) string {
	name := strings.TrimSpace(requested)
	if name == "" {
		name = fallback
	}
	return name + ext
}

// runZip 은 고른 인증서 파일들을 하나의 zip 으로 묶는다.
func runZip(requestedName string) error {
	newFile := outputName(requestedName, "gossl_zip_output", ".zip")

	certFile, err := internal.DirGrepX509()
	if err != nil {
		return panicRed(err)
	}

	selectList, err := internal.AskMultiSelect("Choose the files to compress", certFile.Name)
	if err != nil {
		return panicRed(err)
	}
	if len(selectList) == 0 {
		return panicRed(fmt.Errorf("no file selected"))
	}

	file, err := os.OpenFile(newFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return panicRed(err)
	}
	defer file.Close()

	zipw := zip.NewWriter(file)
	for _, filename := range selectList {
		if err := internal.AppendFile(filename, zipw); err != nil {
			zipw.Close()
			return panicRed(err)
		}
	}
	if err := zipw.Close(); err != nil {
		return panicRed(err)
	}

	fmt.Printf(color.HiGreenString("📄 %s created successfully\n"), newFile)
	return nil
}
