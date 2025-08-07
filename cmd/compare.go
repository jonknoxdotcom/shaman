/*
Copyright © 2025 Jon Knox <jon@k2x.io>
*/
package cmd

import (
	"bufio"
	"fmt"
	"log/slog"
	"os"
	"strings"

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
	compareCmd.Flags().BoolVarP(&cli_long, "long", "l", false, "Describe deletes in long form (in context)")
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
	if !cli_long {
		// short form (just the overlaps in B)
		removalSlice := make([]string, 0, 10)                              // shas is the minimum size - likely to grow
		rows = ssfSelectNameByScoreboard(files[1], overlap, &removalSlice) // not sure
		slog.Debug("size of removal list", "rows", len(removalSlice))

		fmt.Printf("# Commands to delete %d overlapping files from %s\n", rows, files[1])
		for _, fndel := range removalSlice {
			fmt.Printf("rm \"%s\"\n", bashEscape(fndel))
		}
	} else {
		// long form (show all files in B, with the dupes prefixed with "rm"s)
		var r *os.File
		r, err := os.Open(files[1])
		if err != nil {
			abort(4, "Can't open "+files[1]+" - stuck!")
		}
		defer r.Close()

		var s string
		var lineno int
		scanner := bufio.NewScanner(r)
		for scanner.Scan() {
			s = scanner.Text()
			lineno++

			// skip comments
			if len(s) == 0 || s[0:1] == "#" {
				// drop comments or empty lines
				continue
			}

			// skip corrupted
			pos1 := strings.Index(s, " ")
			if pos1 == -1 || pos1 < 55 {
				fmt.Printf("Skipping line %d - Invalid format (pos %d)\n", lineno, pos1)
				continue
			}

			// get rest of fields
			sha := s[0:43]
			//id := s[0:pos1]
			pos2 := strings.Index(s, " :")
			name := s[pos2+2:]

			// check for display vs delete
			if overlap[sha] {
				fmt.Printf("rm \"%s\"\n", bashEscape(name))
			} else {
				fmt.Printf("#   %s \n", bashEscape(name))
			}

		}

	}
}
