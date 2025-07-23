/*
Copyright © 2025 Jon Knox <jon@k2x.io>
*/
package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// anonymiseCmd represents the anonymise command
var anonymiseCmd = &cobra.Command{
	Use:   "anonymise",
	Short: "Remove all data except SHA hashes from file",
	Long: `Removes the filename, size and last used information from an .ssf file to leave only the hashes - useful
when you want to have a very small .ssf for the purposes of checking for the presence of files without wanting to 
disclose the filenames such as a list of customer names, account codes or other related personally-identifiable 
information (PII).  An .ssf with only hashes can still be used for comparisons.`,
	Aliases: []string{"ano", "anonymize"},
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("anonymise called")
	},
}

func init() {
	rootCmd.AddCommand(anonymiseCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// anonymiseCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// anonymiseCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
