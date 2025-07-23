/*
Copyright © 2025 Jon Knox <jon@k2x.io>
*/
package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// biggestCmd represents the biggest command
var biggestCmd = &cobra.Command{
	Use:     "biggest",
	Short:   "Show the names of the largest files",
	Long:    `Finds the top-10 largest files in an .ssf file`,
	Aliases: []string{"big", "largest", "lar"},
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("biggest called")
	},
}

var bcount uint = 10

func init() {
	rootCmd.AddCommand(biggestCmd)

	// *FIXME*
	//generateCmd.Flags().Uint(&bcount, "count", "c", 10, "Specify number of files to show (default: 10)")

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// biggestCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// biggestCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
