/*
Copyright © 2025 Jon Knox <jon@k2x.io>
*/
package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strconv"

	"github.com/spf13/cobra"
)

// updateCmd represents the update command
var updateCmd = &cobra.Command{
	Use:   "update",
	Short: "Update an existing SSF file",
	Long:  `Update an existing SSF file`,
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
	// Check whether file specified and if so that it does not yet exist and that it ends ".ssf"
	var w *bufio.Writer
	if len(args) == 1 {
		// named file - check it's a valid name
		fn := args[0]
		if len(fn) < 5 || fn[len(fn)-4:] != ".ssf" {
			abort(6, "Output file '"+fn+"' is not an '.ssf'")
		}
		// do file read test (want it to fail)
		_, err := os.Open(fn)
		if err == nil {
			abort(6, "Output file '"+fn+"' already exists")
		}
		// open for writing (on 'w' writer handle)
		file_out, err := os.Create(fn)
		if err != nil {
			abort(4, "Internal error #4: ")
		}
		defer file_out.Close()
		//w = bufio.NewWriter(file_out)
		w = bufio.NewWriterSize(file_out, 64*1024*1024) // whopping
	} else {
		// no file given, so use stdout
		w = bufio.NewWriterSize(os.Stdout, 500) // more 'real time'
	}

	// Get the encoding path
	var startpath string = "."
	if cli_path != "" {
		startpath = cli_path // add validation here
	}

	// Call the tree walker
	tf, tb, err := WalkTree(startpath, w)
	if err != nil {
		abort(5, "Internal error #5: ")
	}

	// Optional totals statement
	if cli_totals {
		out := fmt.Sprintf("# %d files, %d bytes", tf, tb)
		fmt.Fprintln(w, out)
	}

	// This directory reader uses the new os.ReadDir (req 1.16)
	// https://benhoyt.com/writings/go-readdir/

	// Optional duplicates statement
	done_header := false
	if cli_dupes {
		for id, times := range dupes {
			if times > 1 {
				if !done_header {
					fmt.Fprintln(w, "# ----------------- Duplicates -----------------")
					done_header = true
				}
				fmt.Fprintln(w, "# "+id+" x"+strconv.Itoa(times))
			}
		}
		if !done_header {
			fmt.Fprintln(w, "# There were no duplicates")
		}
	}

	w.Flush()
}
