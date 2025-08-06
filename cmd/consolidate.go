/*
Copyright © 2025 Jon Knox <jon@k2x.io>
*/
package cmd

import (
	"github.com/spf13/cobra"
)

// -------------------------------- Cobra management -------------------------------

// consolidateCmd represents the consolidate command
var consolidateCmd = &cobra.Command{
	Use:   "consolidate",
	Short: "Combine entries of an anonymous or anonymous/modify files",
	Long: `shaman consolidate
De-duplicates an anonymous type file. Output is sorted. Where modify times are present, outputs the earliest modify date.
Usage examples:
   shaman con input.ssf                           # writes to stdout
   shaman con input.ssf --overwrite               # overwrites file
   shaman con input.ssf output.ssf                # writes to new file
   shaman con input.ssf output.ssf  --no-modify   # same, but drops the modify field
Each command applies to the pure anon (SHA only) or anon/modify (SHA and modify time) files.
Later: year boundary of possible dates (gets rid of unix 0 problem) -- e.g. '--year 1999'
`,
	Aliases: []string{"con"},
	GroupID: "G3",

	Args: cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		con(args)
	},
}

func init() {
	rootCmd.AddCommand(consolidateCmd)

	consolidateCmd.Flags().BoolVarP(&cli_overwrite, "overwrite", "o", false, "Overwrite input file")
}

// ----------------------- Consolidate function below this line -----------------------

func con(args []string) {
	num, _, _ := getSSFs(args)
	if num > 1 {
		abort(8, "Too many .ssf files specified)")
	}

}
