/*
Copyright © 2025 Jon Knox <jon@k2x.io>
*/
package cmd

import (
	"github.com/spf13/cobra"

	"bufio"
	"fmt"
	"log/slog"
	"os"
	"strings"
)

// -------------------------------- Cobra management -------------------------------

// updateCmd represents the update command
var updateCmd = &cobra.Command{
	Use:     "update",
	Short:   "Update an existing SSF file",
	Long:    `Update an existing SSF file`,
	Aliases: []string{"upd"},
	GroupID: "G1",
	Run: func(cmd *cobra.Command, args []string) {
		upd(args)
	},
}

func init() {
	rootCmd.AddCommand(updateCmd)

	// NB: no anonymous switch for update (also, be aware, cannot update an anonymous file)
	updateCmd.Flags().StringVarP(&cli_path, "path", "p", "", "Path to directory to scan (default is current directory)")
	updateCmd.Flags().IntVarP(&cli_format, "format", "f", 0, "Format/anonymisation level 1..5 (default: 5)")
	//updateCmd.Flags().BoolVarP(&cli_dupes, "dupes", "d", false, "Whether to show dupes (as comments) on completion")
	//updateCmd.Flags().BoolVarP(&cli_grand, "grand-totals", "g", false, "Display grand totals of bytes/files on completion")
	//updateCmd.Flags().BoolVarP(&cli_summary, "summary", "s", false, "Summarise differences (do not update the reference .ssf)")
	updateCmd.Flags().BoolVarP(&cli_overwrite, "overwrite", "o", false, "Replace input .ssf with updated one (if changed)")
	updateCmd.Flags().BoolVarP(&cli_rehash, "re-hash", "r", false, "Re-hash files for maximum integrity (compromise detection)")
	updateCmd.Flags().BoolVarP(&cli_verbose, "verbose", "v", false, "Give running commentary of update")
	updateCmd.Flags().BoolVarP(&cli_nodot, "no-dot", "", false, "Do not include files/directories beginning '.'")
}

// ----------------------- Update function below this line -----------------------

func upd(args []string) {
	var fnr string      // filename for reading
	var fnw string      // where to write to (filename to open)
	var w *bufio.Writer // buffer writer
	var form int = 5    // format defaults to 5

	// for update, the format default is 5 (full)
	if cli_format != 0 {
		form = cli_format
	}

	// process CLI
	num, files, found := getSSFs(args)
	slog.Debug("cli handler", "num", num, "files", files, "found", found)
	switch true {
	case num > 2:
		abort(8, "Too many .ssf files - expected one or two")
	case num < 1:
		abort(9, "Input file not specified")
	case !found[0]:
		abort(6, "SSF file '"+files[0]+"' does not exist")
	case num > 1 && found[1]:
		fmt.Println("Output file '" + files[1] + "' will be overwritten")
	}

	// create reader from fnr get got from getSSF
	fnr = files[0]
	var r *os.File
	r, err := os.Open(fnr)
	if err != nil {
		abort(4, "Internal error #4: ")
	}
	defer r.Close()

	// create writer as same file with ".temp" suffix
	if num == 1 && !cli_overwrite {
		// One file given, nowhere to write output (quick though)
		fnw = ""
		if cli_rehash {
			fmt.Println("Slow Test - nothing will be written: (add '-o' if this is wrong)")
			fmt.Println("** Integrity check / all files re-hashed **")
		} else {
			fmt.Println("Dry-run of update (save by giving second file, or write back with '-o')")
		}
	} else if num == 1 && cli_overwrite {
		// One file given with --overwrite switch
		fnw = fnr + ".temp"
		fmt.Println("Updating " + fnr + " (will be overwritten if any changes):")
	} else if num == 2 {
		// Two files given - from A to B
		fnw = files[1]
		fmt.Println("Updating " + fnr + " => " + fnw + ":")
	} else {
		// (should not happen)
		abort(3, "unexpected update")
	}

	// open writing buffer (if used)
	w = writeInit(fnw)
	amWriting := (fnw != "")

	// get tree start, and initiate producer channel
	var startpath string = "."
	if cli_path != "" {
		startpath = cli_path // add validation here
	}
	fileQueue := make(chan triplex, 4096)
	go func() {
		defer close(fileQueue)
		walkTreeYieldFilesToChannel(startpath, fileQueue, cli_nodot)
	}()

	// for now, perform copy (as a test) using scanner on 'r' buffer, max line is 64k
	var lineno int = 0 // needed for error reporting on .ssf file corruptions
	var verbosity int = 1
	if cli_verbose {
		verbosity = 2
	} else {
		fmt.Print("Processing")
	}

	trip_name, trip_modt, trip_size := getNextTriplex(fileQueue)
	// fmt.Println("Tri #1: ", trip_name, trip_modt, trip_size)
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		// process the line from scanner (from the SSF file)
		s := scanner.Text()
		lineno++
		//fmt.Println(lineno, s)

		// drop comments or empty lines
		if len(s) == 0 || s[0:1] == "#" {
			continue
		}

		// chop up s to get fields *FIXME* add annotation handling here **
		pos := strings.IndexByte(s, 32)
		if pos == -1 || pos < 55 {
			fmt.Printf("Deleting line %d - Invalid format on line (pos %d)\n", lineno, pos)
			ndel++
			continue
		}
		ssf_shab64 := s[0:43]
		ssf_modtime := s[43:51]
		ssf_length := s[51:pos]
		ssf_name := restoreLine(s[pos+2:]) // *FIXME* for "A" records

		// fmt.Println("SSF #1: ", ssf_name, ssf_modtime, ssf_length)

		// 1/5 Check for empty triplex
		if trip_name == "" {
			//fmt.Println("[break! #1]")
			break
		}

		// 2/5 If the filesystem is providing names before the current one, we need to process and add them
		if trip_name < ssf_name {
			for trip_name < ssf_name {
				// write record, lazy hash (generated by writer if needed)
				writeRecord(w, amWriting, form, verbosity, "N", "", trip_modt, trip_size, trip_name, "")

				trip_name, trip_modt, trip_size = getNextTriplex(fileQueue)
				// fmt.Println("Tri #2: ", trip_name, trip_modt, trip_size)
				if trip_name == "" {
					break
				}
			} // fall out of this for when trip_name >= ssf_name
		}

		// 3/5 If we are at a matching name, we need to determine if a re-hash is required
		if trip_name == ssf_name {
			trip_name = "" // we do this so that 'continuation' knows not to duplicate
			if ssf_modtime == trip_modt && ssf_length == trip_size && !cli_rehash {
				// no change (assumed on soft criteria) - pass through
				writeRecord(w, amWriting, form, verbosity, "U", ssf_shab64, trip_modt, trip_size, ssf_name, "")
			} else {
				// has changed - get new digest
				_, sha_b64, _ := getFileSha256(ssf_name)

				flag := ""
				if ssf_modtime != trip_modt {
					flag += "T"
				}
				if ssf_length != trip_size {
					flag += "S"
				}
				if ssf_shab64 != sha_b64 {
					flag += "H"
				}

				if flag != "" {
					// changed
					writeRecord(w, amWriting, form, verbosity, "C", sha_b64, trip_modt, trip_size, ssf_name, flag)
				} else {
					// verified and unchanged
					writeRecord(w, amWriting, form, verbosity, "V", sha_b64, trip_modt, trip_size, ssf_name, flag)
				}
			}

			trip_name, trip_modt, trip_size = getNextTriplex(fileQueue)
			// fmt.Println("Tri #3: ", trip_name, trip_modt, trip_size)

			continue
		}

		// 4/5 The file stream is before current, so del 'not seen' ssf file (if non-empty)
		if ssf_name != "" && trip_name > ssf_name {
			writeRecord(w, amWriting, form, verbosity, "D", "", "", "", ssf_name, "") // verified unchanged
		}
	}

	// 5/5 Input file exhausted - check for 1x pending, and tail of triplex channel
	if trip_name == "" {
		trip_name, trip_modt, trip_size = getNextTriplex(fileQueue)
		// fmt.Println("Tri #4: ", trip_name, trip_modt, trip_size)

	}
	for trip_name != "" {
		writeRecord(w, amWriting, form, verbosity, "N", "", trip_modt, trip_size, trip_name, "") // new

		trip_name, trip_modt, trip_size = getNextTriplex(fileQueue)
		// fmt.Println("Tri #5: ", trip_name, trip_modt, trip_size)
	}

	// End of processing - report the number of changes
	if verbosity == 1 {
		fmt.Println()
	}
	nchanges := nnew + ndel + nchg
	updateDetails := fmt.Sprintf("(new=%d, deleted=%d, changed=%d, unchanged=%d)", nnew, ndel, nchg, nunc)

	switch nchanges {
	case 0:
		fmt.Println("There were 0 changes - " + fnr + " still good")
	case 1:
		fmt.Println("There was 1 change " + updateDetails)
	default:
		fmt.Println("There were", nchanges, "changes "+updateDetails)
	}
	slog.Debug("changes", "new", nnew, "del", ndel, "nchg", nchg, "unchanged", nunc, "tf", tf, "tb", tb)

	// Optional totals and duplicates statements + file shuffle and final buffer flush
	if amWriting {
		reportGrandTotals(w, tf, tb)
		reportDupes(w)
		w.Flush()

		if cli_overwrite {
			if nchanges == 0 {
				// destroy tempfile
				os.Remove(fnw)
			} else if nchanges > 0 {
				fmt.Println("Overwriting " + fnr)
				os.Remove(fnr)
				os.Rename(fnw, fnr)
				os.Exit(1)
			} else if cli_grand || cli_dupes {
				// if the ssf file was correct, then we do not update it to preserve its timestamp
				// but this means that we have to leave its total/dupes statements as-is - i.e. if
				// we wrote these, then this metadata change would be the only change to the ssf
				fmt.Println("Ignoring --grand-total and/or --dupes in order to retain file timestamp")
			}
		}
	}

	os.Exit(0) //explicit (because we're a rc=0 or rc=1 depending on whether any changes)
}
