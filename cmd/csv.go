/*
Copyright © 2025 Jon Knox <jon@k2x.io>
*/
package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// csvCmd represents the csv command
var csvCmd = &cobra.Command{
	Use:   "csv",
	Short: "Convert SSF file into CSV format (suitable for Excel)",
	Long:  `Convert SSF file into CSV format (suitable for Excel)`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("csv called")
	},
}

func init() {
	rootCmd.AddCommand(csvCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// csvCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// csvCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
