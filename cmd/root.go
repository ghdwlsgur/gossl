package cmd

import (
	"fmt"
	"os"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	rootCmd = &cobra.Command{
		Use:   "gossl",
		Short: `gossl is an interactive tool that allows you to integrate certificates, look up certificates and private keys, split integrated certificate files by root, intermediate, and leaf certificates, or view certificate information applied to a domain by A record. We will update the certificate format that changes for each ca.`,
		Long:  `gossl is an interactive tool that allows you to integrate certificates, look up certificates and private keys, split integrated certificate files by root, intermediate, and leaf certificates, or view certificate information applied to a domain by A record. We will update the certificate format that changes for each ca.`,
	}
)

func panicRed(err error) {
	fmt.Println(color.RedString("[err] %s", err.Error()))
	os.Exit(1)
}

func Execute(version string) {
	rootCmd.Version = version
	if err := rootCmd.Execute(); err != nil {
		panicRed(err)
	}
}

func initConfig() {
	args := os.Args[1:]
	_, _, err := rootCmd.Find(args)
	if err != nil {
		panicRed(err)
	}
}

func init() {
	cobra.OnInitialize(initConfig)
}
