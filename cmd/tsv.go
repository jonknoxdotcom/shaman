/*
Copyright © 2025 Jon Knox <jon@k2x.io>
*/
package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// tsvCmd represents the tsv command
var tsvCmd = &cobra.Command{
	Use:   "tsv",
	Short: "Convert SSF file into TSV format (suitable for Excel)",
	Long:  `Convert SSF file into TSV format (suitable for Excel)`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("tsv called")
	},
}

func init() {
	rootCmd.AddCommand(tsvCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// tsvCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// tsvCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
