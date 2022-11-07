package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var (
	checkCommand = &cobra.Command{
		Use:   "check",
		Short: "test",
		Long:  "test",
		Run: func(_ *cobra.Command, _ []string) {
			// ctx := context.Background()
			fmt.Println("good")
		},
	}
)

func init() {
	rootCmd.AddCommand(checkCommand)
}
