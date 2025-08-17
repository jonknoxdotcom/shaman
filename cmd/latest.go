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

// latestCmd represents the latest command
var latestCmd = &cobra.Command{
	Use:     "latest",
	Short:   "Show the names of the latest files",
	Long:    `Finds the top-50 latest files in an .ssf file`,
	Aliases: []string{"lat"},
	Args:    cobra.MaximumNArgs(10), // handle in code
	GroupID: "G2",

	Run: func(cmd *cobra.Command, args []string) {
		lat(args)
	},
}

func init() {
	rootCmd.AddCommand(latestCmd)

	latestCmd.Flags().IntVarP(&cli_count, "count", "c", 20, "Specify number of files to show (default: 20)")
	latestCmd.Flags().StringVarP(&cli_discard, "discard", "", "", "Path to exclude from results")
	latestCmd.Flags().BoolVarP(&cli_equal, "equal", "e", false, "Show equal time/hash in listing")
	latestCmd.Flags().BoolVarP(&cli_nodot, "no-dot", "", false, "Do not include files/directories beginning '.'")
}

// ----------------------- "Latest" function below this line -----------------------

func lat(args []string) {
	// Make sure we have a single input file that exists / error appropriately
	num, files, found := getSSFs(args)
	slog.Debug("cli handler", "num", num, "files", files, "found", found)
	switch true {
	case num > 8:
		abort(8, "Too many .ssf files specified - eight is enough")
	case num < 1:
		abort(9, "Need an SSF file to perform largest file check")
	case !found[0]:
		abort(6, "Input SSF file '"+files[0]+"' does not exist")
	}
	fn := files[0]

	// Default 20, user over-ride with '--count', maximum 999
	var thresh string = "00000000" // modtime is 08x format
	cli_count = min(cli_count, 999)
	title := fmt.Sprintf("LATEST %d CHANGED FILES", cli_count)
	topInit(cli_count, thresh)

	// fixed use of .ssf file (no local)
	var r *os.File
	r, err := os.Open(fn)
	if err != nil {
		abort(4, "Can't open "+fn+" - stuck!")
	}
	defer r.Close()

	var s string
	var lineno int
	scanner := bufio.NewScanner(r)

	for scanner.Scan() {
		s = scanner.Text()
		lineno++
		if len(s) == 0 || s[0:1] == "#" {
			// drop comments or empty lines
			continue
		}

		// check size with least kerfuffle
		pos1 := strings.Index(s, " ")
		if pos1 == -1 || pos1 < 55 {
			fmt.Printf("Skipping line %d - Invalid format (pos %d)\n", lineno, pos1)
			continue
		}
		key := s[43:51] // 8ch
		if key < thresh {
			// off the bottom - no need to do a Add attempt
			continue
		}

		// get rest of fields
		id := s[0:pos1]
		pos2 := strings.Index(s, " :")
		name := s[pos2+2:]

		// check for discard
		if cli_discard != "" && len(name) >= len(cli_discard) && name[:len(cli_discard)] == cli_discard {
			continue
		}

		thresh = topAdd(key, id, name)
	}

	topReportByDate(title)
}
