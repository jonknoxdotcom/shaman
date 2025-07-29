/*
Copyright © 2025 Jon Knox <jon@k2x.io>
*/
package cmd

import (
	"fmt"
	"log/slog"

	"github.com/spf13/cobra"
)

// -------------------------------- Cobra management -------------------------------

// compareCmd represents the compare command
var compareCmd = &cobra.Command{
	Use:     "compare",
	Short:   "Compare two .ssf files",
	Long:    `Compares two files (at hash level) and produces bash-type scripts to delete items between.`,
	Aliases: []string{"com"},
	GroupID: "G2",
	Args:    cobra.MaximumNArgs(99), // handle in code
	Run: func(cmd *cobra.Command, args []string) {
		com(args)
	},
}

func init() {
	rootCmd.AddCommand(compareCmd)
	compareCmd.Flags().BoolVarP(&cli_del_b, "del-b", "", false, "Generate 'rm' for files in B which are present in A")
}

// ----------------------- Generate function below this line -----------------------

func com(args []string) {
	// Make sure we have a single input file that exists / error appropriately
	num, files, found := getSSFs(args)
	slog.Debug("cli handler", "num", num, "files", files, "found", found)
	switch true {
	case num > 2:
		abort(8, "Too many .ssf files specified - expected two")
	case num < 2:
		abort(9, "Two SSF files are needing to make a comparison")
	case !found[0]:
		abort(6, "Source SSF file '"+files[0]+"' does not exist")
	case !found[1]:
		abort(6, "Target SSF file '"+files[1]+"' does not exist")
	}

	// Work out which smallest
	len_a := ssfRecCount(files[0])
	len_b := ssfRecCount(files[1])
	var smaller int = 0
	if len_b < len_a {
		smaller = 1
	}
	slog.Debug("determined which file has fewest records", "a", len_a, "b", len_b, "use", files[smaller])

	// Use scoreboarding to optimize processing
	var overlap = map[string]bool{} // scoreboard for smaller collection

	// fill scoreboard with 'false' for each file in smaller set
	shas, rows := ssfScoreboardRead(files[smaller], overlap, false)
	slog.Debug("read smaller to get uniq shas", "file", files[smaller], "records", rows, "uniques", shas)

	// mark true for any scoreboard keys in larger target
	shas, rows = ssfScoreboardMark(files[1-smaller], overlap, true)
	slog.Debug("use larger to mark shared", "file", files[1-smaller], "marked", rows, "processed", shas)

	// strip map of non-overlaps
	shas = ssfScoreboardRemove(overlap, false)
	slog.Debug("intersection", "score", shas)

	// how many overlaps?
	if shas == 0 {
		abort(0, fmt.Sprintf("There are no overlapping records between '%s' and '%s'", files[0], files[1]))
	}

	// generate bash command to remove files in B that were in A
	removalSlice := make([]string, 0, 10)                              // shas is the minimum size - likely to grow
	rows = ssfSelectNameByScoreboard(files[1], overlap, &removalSlice) // not sure
	rows = ssfSelectNameByScoreboard(files[1], overlap, &removalSlice) // not sure
	rows = ssfSelectNameByScoreboard(files[1], overlap, &removalSlice) // not sure
	slog.Debug("size of removal list", "rows", len(removalSlice))

	fmt.Printf("# Commands to delete %d overlapping files from %s\n", rows, files[1])
	for _, fndel := range removalSlice {
		fmt.Printf("rm \"%s\"\n", bashEscape(fndel))
	}
}
