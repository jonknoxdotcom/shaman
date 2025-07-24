/*
Copyright © 2025 Jon Knox <jon@k2x.io>
*/
package cmd

import (
	"github.com/spf13/cobra"

	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// updateCmd represents the update command
var updateCmd = &cobra.Command{
	Use:     "update",
	Short:   "Update an existing SSF file",
	Long:    `Update an existing SSF file`,
	Aliases: []string{"upd"},
	Run: func(cmd *cobra.Command, args []string) {
		upd(args)
	},
}

func init() {
	rootCmd.AddCommand(updateCmd)

	// NB: no anonymous switch for update (also, be aware, cannot update an anonymous file)
	updateCmd.Flags().StringVarP(&cli_path, "path", "p", "", "Path to directory to scan (default is current directory)")
	updateCmd.Flags().BoolVarP(&cli_dupes, "dupes", "d", false, "Whether to show dupes (as comments) on completion")
	updateCmd.Flags().BoolVarP(&cli_totals, "totals", "t", false, "Display count of bytes and files on completion")
}

// ----------------------- Update function below this line -----------------------

func upd(args []string) {
	// Make sure we have a single input file that exists / error appropriately
	num, files, found := getSSFs(args)
	if num > 1 {
		abort(8, "Too many .ssf files specified")
	}
	if num < 1 {
		abort(10, "Input file not specified")
	}
	fn := files[0]
	if !found[0] {
		abort(6, "Input SSF file '"+fn+"' does not exists")
	}

	// Create reader and writer pair
	var r *os.File
	var w *bufio.Writer

	// open for reading (add some buffering?)
	r, err := os.Open(fn)
	if err != nil {
		abort(4, "Internal error #4: ")
	}
	defer r.Close()

	// force create candidate in same location, end .temp, for writing (on 'w' writer handle)
	fnw := fn + ".temp"
	file_out, err := os.Create(fnw)
	if err != nil {
		abort(4, "Internal error #4: ")
	}
	defer file_out.Close()
	w = bufio.NewWriterSize(file_out, 64*1024*1024)

	// Copy (as a test) using scanner, max line is 64k
	var lineno int = 0
	var tf int64 = 0
	var tb int64 = 0
	scanner := bufio.NewScanner(r)

	for scanner.Scan() {
		s := scanner.Text()
		lineno++
		// drop comments or empty lines
		if len(s) == 0 || s[0:1] == "#" {
			continue
		}
		// extract fields
		tf++
		pos := strings.IndexByte(s, 32)
		if pos == -1 {
			abort(4, "Invalid format on line "+strconv.Itoa(lineno))
		}
		id := s[0:pos]
		sha_b64 := s[0:43]
		// fmt.Println("'" + id + "'")
		nbytes, err := strconv.ParseInt(id[51:], 16, 0)

		// fmt.Println("'" + id[51:] + "'")
		// fmt.Println("'" + strconv.Itoa(int(nbytes)) + "'")

		if err != nil {
			abort(4, "Invalid format on line "+strconv.Itoa(lineno))
		}
		tb += nbytes
		if cli_dupes {
			dupes[sha_b64] = dupes[sha_b64] + 1
		}

		fmt.Fprintln(w, s)
	}

	// Optional totals and duplicates statements
	state_totals(w, tf, tb)
	state_dupes(w)

	// Determine whether to keep existing file or replace
	//...

	w.Flush()
}
