package cmd

import (
	"fmt"
	"strings"

	"github.com/fatih/color"
	"github.com/ghdwlsgur/gossl/internal"
	"github.com/spf13/cobra"
)

var (
	downloadCommand = &cobra.Command{
		Use:   "download",
		Short: "download root certificate",
		Long:  "download root certificate",
		RunE: func(cmd *cobra.Command, args []string) error {
			var (
				err error
				r   internal.RootYaml
			)

			if err = cobra.NoArgs(cmd, args); err != nil {
				return panicRed(err)
			}

			err = internal.ParsingYaml(&r)
			if err != nil {
				return panicRed(err)
			}

			rootName, err := internal.AskSelect("Select root certificate", r.Root.GetNameListOwnURL())
			if err != nil {
				return panicRed(err)
			}

			url := r.Root.FindURL(rootName)
			fileName := fmt.Sprintf("%s.pem", strings.ReplaceAll(rootName, " ", ""))
			err = internal.DownloadCertificate(url, fileName)
			if err != nil {
				return panicRed(err)
			}
			fmt.Printf("%s %s %s",
				color.HiBlackString("🎉 [ROOT CERTIFICATE]"),
				color.HiWhiteString(fileName),
				color.HiGreenString("Download Complete 🎉\n"))

			return nil
		},
	}
)

func init() {
	rootCmd.AddCommand(downloadCommand)
}
