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

// -------------------------------- Cobra management -------------------------------

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

	// Get the scanning path
	var startpath string = "."
	if cli_path != "" {
		startpath = cli_path // add validation here
	}

	//  Set up producer channel
	fileQueue := make(chan triplex, 4096)
	go func() {
		defer close(fileQueue)
		walkTreeToChannel(startpath, fileQueue)
	}()

	// Retrieve first reference record from file stream
	//t := chan<-

	// ** now ignore that we have this source and just go about copying data from old to new **

	// create reader from fn get got from getSSF
	var r *os.File
	r, err := os.Open(fn)
	if err != nil {
		abort(4, "Internal error #4: ")
	}
	defer r.Close()

	// create writer as same file with ".temp" suffix
	var w *bufio.Writer
	fnw := fn + ".temp"
	file_out, err := os.Create(fnw)
	if err != nil {
		abort(4, "Internal error #4: ")
	}
	defer file_out.Close()
	w = bufio.NewWriterSize(file_out, 64*1024*1024)

	// for now, perform copy (as a test) using scanner on 'r' buffer, max line is 64k
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
	reportTotals(w, tf, tb)
	reportDupes(w)

	// Determine whether to keep existing file or replace
	//...

	w.Flush()
}
