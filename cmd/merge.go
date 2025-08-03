/*
Copyright © 2025 Jon Knox <jon@k2x.io>
*/
package cmd

import (
	"github.com/spf13/cobra"
)

// tsvCmd represents the tsv command
var mergeCmd = &cobra.Command{
	Use:     "merge",
	Short:   "Merge two SSF files",
	Long:    `Merge two SSF files - with optional path 'mount point'`,
	Args:    cobra.MaximumNArgs(2),
	GroupID: "G3",
	Run: func(cmd *cobra.Command, args []string) {
		mer(args)
	},
}

func init() {
	rootCmd.AddCommand(tsvCmd)

	mergeCmd.Flags().StringVarP(&cli_path, "path", "p", "", "Optional path that mergefile to be prefixed with")
}

// ----------------------- Merge function below this line -----------------------

func mer(args []string) {
}
