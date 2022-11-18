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
		Short: `gossl is an interactive CLI that compares certificate file types and md5 hash, or curls results from the origin domain's name servers to the target domain.`,
		Long:  `gossl is an interactive CLI that compares certificate file types and md5 hash, or curls results from the origin domain's name servers to the target domain.`,
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
