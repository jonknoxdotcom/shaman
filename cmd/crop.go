/*
Copyright © 2025 Jon Knox <jon@k2x.io>
*/
package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// cropCmd represents the crop command
var cropCmd = &cobra.Command{
	Use:   "crop",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("crop called")
	},
}

func init() {
	rootCmd.AddCommand(cropCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// cropCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// cropCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
