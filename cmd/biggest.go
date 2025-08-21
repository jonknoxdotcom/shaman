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

// biggestCmd represents the biggest command
var biggestCmd = &cobra.Command{
	Use:     "biggest",
	Short:   "Show the names of the largest files",
	Long:    `Finds the top-10 largest files in an .ssf file`,
	Aliases: []string{"big", "largest", "lar"},
	Args:    cobra.MaximumNArgs(99), // handle in code
	GroupID: "G2",

	Run: func(cmd *cobra.Command, args []string) {
		big(args)
	},
}

func init() {
	rootCmd.AddCommand(biggestCmd)

	biggestCmd.Flags().IntVarP(&cli_count, "count", "c", 20, "Specify number of files to show (default: 20)")
	biggestCmd.Flags().StringVarP(&cli_discard, "discard", "", "", "Path to exclude from results")
	biggestCmd.Flags().BoolVarP(&cli_equal, "equal", "e", false, "Show subsequent equal size or hash")
	biggestCmd.Flags().BoolVarP(&cli_nodot, "no-dot", "", false, "Do not include files/directories beginning '.'")
}

// ----------------------- "Biggest" (largest) function below this line -----------------------

func bigFile(fn string, prefix string) int {
	// open file
	r, err := os.Open(fn)
	if err != nil {
		fmt.Println("Unexpected problem opening file " + fn)
		return 0
	}
	defer r.Close()

	// get the threshold
	thresh := topKeys[topDepth-1]

	// process lines
	var s string
	var lineNumber int
	var linesAdded int
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		s = scanner.Text()
		lineNumber++
		if len(s) == 0 || s[0:1] == "#" {
			// drop comments or empty lines
			continue
		}

		// check size with least kerfuffle
		pos1 := strings.Index(s, " ")

		if pos1 == -1 && len(s) == 43 {
			fmt.Printf("Seeing anonymous records in %s - skipping\n", fn)
			return 0
		}
		if pos1 == -1 || pos1 < 55 {
			fmt.Printf("Skipping line %d - Invalid format (position %d, length %d)\n", lineNumber, pos1, len(s))
			continue
		}
		temp := "000000" + s[51:pos1] // pad - better way?
		key := temp[len(temp)-10:]
		if key <= thresh {
			// off the bottom - no need to do a Add attempt
			continue
		}

		// get rest of fields
		id := s[0:pos1]
		pos2 := strings.Index(s, " :")
		name := prefix + s[pos2+2:]

		// drop if files or directories begins "." and nodot asserted
		if cli_nodot && (strings.Contains(name, "/.") || name[0:1] == ".") {
			continue
		}

		thresh = topAdd(key, id, name)
		linesAdded++
	}
	return linesAdded
}

func bigLocal(path string) int {
	// create tree walker channel
	fileQueue := make(chan triplex, 4096)
	go func() {
		defer close(fileQueue)
		walkTreeYieldFilesToChannel(path, fileQueue, cli_nodot)
	}()

	// get the threshold
	// thresh := topKeys[topDepth-1]

	// process lines
	lineno := 0
	for filerec := range fileQueue {
		// fmt.Println("line", filerec)
		// drop if files or directories begins "." and nodot asserted
		// if cli_nodot && (strings.Contains(filerec.filename, "/.") || filerec.filename[0:1] == ".") {
		// 	continue
		// }

		lineno++
		key := fmt.Sprintf("%010x", filerec.size)
		// if key < thresh {
		// 	// off the bottom - no need to do a Add attempt
		// 	fmt.Println("bottom")
		// 	continue
		// }

		// get rest of fields
		id := filerec.filename
		name := filerec.filename

		_ = topAdd(key, id, name)
	}
	return lineno
}

func big(args []string) {
	// Make sure we have a single input file that exists / error appropriately
	num, files, found := getSSFs(args)
	slog.Debug("cli handler", "num", num, "files", files, "found", found)
	switch true {
	case num > 20:
		abort(8, "Too many .ssf files specified - twenty is enough")
	case num < 0:
		abort(9, "Need an SSF file to perform largest file check")
	case num >= 1 && !found[0]:
		abort(6, "Input SSF file '"+files[0]+"' does not exist")
	}

	// Default 20, user over-ride with '--count', maximum 999
	var thresh string = "0000000000" // size is 010x format
	thresh = ""                      // empty string is before  "0000000000"
	cli_count = min(cli_count, 999)
	//title := fmt.Sprintf("TOP %d FILES BY SIZE", cli_count)
	title := "TOP %d FILES BY SIZE"

	switch true {
	case num == 0: // no files given - use local directory
		title += " in current directory (dupes not identified)"
		topInit(cli_count, thresh)
		lines := bigLocal(".")
		fmt.Printf("Found %d files\n", lines)

	case num == 1:
		topInit(cli_count, thresh)
		lines := bigFile(files[0], "")
		fmt.Printf("Found %d records\n", lines)
	case num > 1:
		title += " for "
		topInit(cli_count, thresh)
		for _, fn := range files {
			lines := bigFile(fn, fn+": ")
			title += fmt.Sprintf(" %s (%d)", fn, lines)
			fmt.Printf("Found %d records in %s\n", lines, fn)
		}
	default:
	}

	topReportBySize(title + "\n")
}
