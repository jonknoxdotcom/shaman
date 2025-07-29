/*
Copyright © 2025 Jon Knox <jon@k2x.io>
*/
package cmd

import (
	"github.com/spf13/cobra"

	"bufio"
	"fmt"
	"os"
)

// -------------------------------- Cobra management -------------------------------

// sumCmd represents the sum command
var sumCmd = &cobra.Command{
	Use:   "sum [file.ssf]",
	Short: "Produce a GNU-style sha256sum check file from an SSF or live directory",
	Long: `shaman sum file.ssh
Generate a GNU-style sha256sum check file from an SSF or live directory.  Typically used with the --path
switch to select a subdirectory. Produces immediately from file, or can calculate live.`,
	Aliases: []string{"sum"},
	Args:    cobra.MaximumNArgs(1),
	GroupID: "G1",
	Run: func(cmd *cobra.Command, args []string) {
		sum(args)
	},
}

func init() {
	rootCmd.AddCommand(sumCmd)

	sumCmd.Flags().StringVarP(&cli_path, "path", "p", "", "Path to directory to use (default is all files)")
}

// ----------------------- Sum function below this line -----------------------

func sum(args []string) {
	num, files, found := getSSFs(args)
	if num > 1 {
		abort(8, "Too many .ssf files specified)")
	}

	// Check whether file specified and if so that it does not yet exist and that it ends ".ssf"
	var w *bufio.Writer
	ticker := false
	if num == 1 {
		// check not already existing
		fn := files[0]
		if found[0] {
			abort(6, "Output file '"+fn+"' already exists")
		}

		// open for writing (on 'w' writer handle)
		file_out, err := os.Create(fn)
		if err != nil {
			abort(4, "Surprisingly, unable to create file "+fn)
		}
		defer file_out.Close()
		//w = bufio.NewWriter(file_out)
		w = bufio.NewWriterSize(file_out, 64*1024*1024) // whopping
		ticker = true
		fmt.Printf("Generating (dot=100)")
	} else {
		// no file given, so use stdout
		w = bufio.NewWriterSize(os.Stdout, 500) // more 'real time'
	}

	// Get the encoding path
	var startpath string = "."
	if cli_path != "" {
		startpath = cli_path // add validation here
	}

	// ------------------------------------------

	// Call the tree walker to sum a file list (as a channel)
	fileQueue := make(chan triplex, 4096)
	go func() {
		defer close(fileQueue)
		walkTreeToChannel(startpath, fileQueue)
	}()

	// process file list to sum SSF records
	var total_files int64
	var total_bytes int64
	for filerec := range fileQueue {
		_, sha_b64 := getFileSha256(filerec.filename)

		outbuf := sha_b64
		if !cli_anon {
			outbuf += fmt.Sprintf("%x%04x :%s", filerec.modified, filerec.size, filerec.filename)
		}
		fmt.Fprintln(w, outbuf)

		if cli_dupes {
			dupes[sha_b64] = dupes[sha_b64] + 1
		}

		// stats and ticks (dot every 100, flush every 500)
		total_bytes += filerec.size
		total_files++
		if ticker && total_files%100 == 0 {
			fmt.Print(".")
		}
		if total_files%500 == 0 {
			w.Flush()
		}
	}

	if ticker {
		fmt.Println(".")
	}

	// Optional totals and duplicates statements
	reportGrandTotals(w, total_files, total_bytes)
	reportDupes(w)

	w.Flush()
}
