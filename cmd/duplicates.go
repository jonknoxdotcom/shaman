/*
Copyright © 2025 Jon Knox <jon@k2x.io>
*/
package cmd

import (
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"strings"

	"github.com/spf13/cobra"
)

// duplicatesCmd represents the duplicates command
var duplicatesCmd = &cobra.Command{
	Use:   "duplicates",
	Short: "Detect multiple copies of same file / generate 'rm' declutter list",
	Long: `Scans an SSF file looking for repeated SHAs, and generates a list of the duplicates as commented-out
bash instructions to delete the files.  Edit this to decide which to delete as appropriate.`,
	Aliases: []string{"dup"},
	GroupID: "G2",
	Args:    cobra.MaximumNArgs(99), // handle in code
	Run: func(cmd *cobra.Command, args []string) {
		dup(args)
	},
}

func init() {
	rootCmd.AddCommand(duplicatesCmd)

	duplicatesCmd.Flags().BoolVarP(&cli_incsha, "include-sha", "", false, "Include SHA on any output")
}

// ----------------------- Duplicate function below this line -----------------------

func dup(args []string) {
	// Make sure we have a single input file that exists / error appropriately
	num, files, found := getSSFs(args)
	slog.Debug("cli handler", "num", num, "files", files, "found", found)
	switch true {
	case num > 1:
		abort(8, "Too many .ssf files specified - expected one")
	case num < 1:
		abort(9, "Need an SSF file to perform dupe-check")
	case !found[0]:
		abort(6, "Input SSF file '"+files[0]+"' does not exist")
	}

	// How big?
	len_a := ssfRecCount(files[0])
	slog.Debug("validate and count", "len", len_a, "file", files[0])
	fmt.Printf("Valid file with %d SSF records\n", len_a)

	// Use scoreboarding to optimize processing
	var multiple = map[string]bool{} // scoreboard for dupe detect
	rows, dupes := ssfScoreboardDupRead(files[0], multiple)
	slog.Debug("dup scoreboard read", "file", files[0], "records", rows, "dupes", dupes)
	fmt.Printf("File %s has %d SHAs with duplicate files\n", files[0], dupes)

	// Strip map of non-duplicates, and quit if none to show
	shas := ssfScoreboardRemove(multiple, false) // unnec
	slog.Debug("duplication", "shas", shas)
	if shas == 0 {
		abort(0, fmt.Sprintf("There are no duplicated files in '%s'", files[0]))
	}

	// FORMING THE SORTED LIST OF DUPES - HOW IT WORKS
	// We generate two maps:
	//   first[]  : key=filename, val=sha  (the first filename to use this sha)
	//   report[] : key=sha, value=2/3/4... lines of \n-separated escaped filenames
	// 1. collect the first names and the report data at same time
	// 2. sort the first table's keys to get report order (firstkeys)
	// 3. step through first[], get the sha, and get the contents of the report[sha]

	// Collect data using pair of maps joined by sha...
	var first = map[string]string{}  // first fn to use sha -> sha
	var report = map[string]string{} // sha -> report text
	nreports, nfiles := sshScoreboardReadMapMap(multiple, files[0], first, report)
	fmt.Printf("Found %d duplicate blocks comprising %d files (potentially %d excess files)\n", nreports, nfiles, nfiles-nreports)

	// Create chunks of answers, sorted by first filename, and write out (optional sha)
	// ref: https://github.com/golang/go/issues/61538 & https://pkg.go.dev/maps#Keys
	firstkeys := slices.Sorted(maps.Keys(first))
	for _, fk := range firstkeys {
		if cli_incsha {
			fmt.Println("# " + first[fk])
		}

		s := fk + "\n" + report[first[fk]]
		for _, line := range strings.Split(s, "\n") {
			fmt.Println("#rm \"" + line + "\"")
		}
		fmt.Println("")
	}
}
