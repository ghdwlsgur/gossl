package cmd

import (
	"fmt"
	"strings"

	"github.com/ghdwlsgur/gossl/internal"
	"github.com/spf13/cobra"
)

var (
	downloadCommand = &cobra.Command{
		Use:   "download",
		Short: "download root certificate",
		Long:  "download root certificate",
		Run: func(_ *cobra.Command, args []string) {
			var (
				err error
				r   internal.RootYaml
			)

			err = internal.ParsingYaml(&r)
			if err != nil {
				panicRed(err)
			}

			rootName, err := internal.AskSelect("Select root certificate", r.Root.GetNameListOwnURL())
			if err != nil {
				panicRed(err)
			}

			url := r.Root.FindURL(rootName)
			fileName := fmt.Sprintf("%s.pem", strings.ReplaceAll(rootName, " ", ""))
			err = internal.DownloadCertificate(url, fileName)
			if err != nil {
				panicRed(err)
			}
		},
	}
)

func init() {
	rootCmd.AddCommand(downloadCommand)
}
