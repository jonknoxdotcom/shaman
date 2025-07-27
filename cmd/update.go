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
	updateCmd.Flags().BoolVarP(&cli_grand, "grand-totals", "g", false, "Display grand totals of bytes/files on completion")
	updateCmd.Flags().BoolVarP(&cli_summary, "summary", "s", false, "Summarise differences (do not update the reference .ssf)")
	updateCmd.Flags().BoolVarP(&cli_overwrite, "overwrite", "o", false, "Replace input .ssf with updated one (if changed)")
	updateCmd.Flags().BoolVarP(&cli_rehash, "re-hash", "r", false, "Re-hash files for maximum integrity (compromise detection)")
}

// ----------------------- Update function below this line -----------------------

func getNextTriplex(fileQueue chan triplex) (fs_name string, fs_modt string, fs_size string) {
	t, ok := <-fileQueue
	///fmt.Println(t)
	if !ok {
		return "", "", ""
	} else {
		return t.filename,
			fmt.Sprintf("%08x", t.modified), // always 8 digits
			fmt.Sprintf("%04x", t.size) // overflows 4-8 digits
	}
}

func upd(args []string) {
	// Make sure we have a single input file that exists / error appropriately
	num, files, found := getSSFs(args)
	if num > 2 {
		abort(8, "Too many .ssf files specified")
	}
	if num < 1 {
		abort(10, "Input file not specified")
	}
	fn := files[0]
	if !found[0] {
		abort(6, "Input SSF file '"+fn+"' does not exist")
	}

	// create reader from fn get got from getSSF
	var r *os.File
	r, err := os.Open(fn)
	if err != nil {
		abort(4, "Internal error #4: ")
	}
	defer r.Close()

	// create writer as same file with ".temp" suffix
	var fnw string // where to write to (filename to open)
	if num == 1 && !cli_overwrite {
		// One file given, nowhere to write output (quick though)
		if cli_rehash {
			fmt.Println("Slow Test - nothing will be written: (add '-o' if this is wrong)")
			fmt.Println("** Integrity check / all files re-hashed **")
		} else {
			fmt.Println("Dry-run of update (to save, give second ssf file, or add '-o' to write back)")
		}
		fnw = ""
	} else if num == 1 && cli_overwrite {
		// One file given with --overwrite switch
		fmt.Println("Updating " + fn + " (will be overwritten if any changes):")
		fnw = fn + ".temp"
	} else if num == 2 {
		// Two files given - from A to B
		fnw = files[1]
		fmt.Println("Updating " + fn + " => " + fnw + ":")

	} else {
		// (should not happen)
		abort(3, "unexpected update")
	}
	amWriting := (fnw != "")

	// open writing buffer (if used)
	var w *bufio.Writer
	if amWriting {
		file_out, err := os.Create(fnw)
		if err != nil {
			abort(4, "Cannot create file "+fnw)
		}
		defer file_out.Close()
		w = bufio.NewWriterSize(file_out, 64*1024*1024)
	}

	// Get tree start, and initiate producer channel
	var startpath string = "."
	if cli_path != "" {
		startpath = cli_path // add validation here
	}
	fileQueue := make(chan triplex, 4096)
	go func() {
		defer close(fileQueue)
		walkTreeToChannel(startpath, fileQueue)
	}()

	// Retrieve first reference record from file stream
	trip_name, trip_modt, trip_size := getNextTriplex(fileQueue)

	// for now, perform copy (as a test) using scanner on 'r' buffer, max line is 64k
	var lineno int = 0 // needed for error reporting on .ssf file corruptions
	var tf int64 = 0   // total files
	var tb int64 = 0   // total bytes

	var nnew = 0
	var ndel = 0
	var nchg = 0
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		// process the line from scanner (from the SSF file)
		s := scanner.Text()
		lineno++
		if len(s) == 0 || s[0:1] == "#" {
			// drop comments or empty lines
			continue
		}

		// chop up s to get fields
		pos := strings.IndexByte(s, 32)
		if pos == -1 {
			abort(4, "Invalid format on line "+strconv.Itoa(lineno))
		}
		id := s[0:pos]
		ssf_shab64 := s[0:43]
		ssf_modtime := s[43:51]
		ssf_length := s[51:pos]
		ssf_name := s[pos+2:]
		ssf_bytes, err := strconv.ParseInt(id[51:], 16, 0)
		if err != nil {
			abort(4, "Invalid format on line "+strconv.Itoa(lineno))
		}
		///fmt.Println("Line #", lineno, " '"+ssf_shab64+"', '"+ssf_modtime+"', '"+ssf_length+"', '"+ssf_name+"' bytes =", ssf_bytes)

		// 1. Check for empty triplex
		if trip_name == "" {
			///fmt.Println("[break1!]")
			break
		}

		// 2. If the filesystem is providing names before the current one, we need to process and add them
		///fmt.Println("1: " + trip_name + " < " + ssf_name)
		if trip_name < ssf_name {
			for trip_name < ssf_name {
				///fmt.Println("Need to add (from trip) [" + trip_name + "]")
				_, sha_b64 := getFileSha256(trip_name)
				///fmt.Println("(hash=" + sha_b64 + ")")
				if amWriting {
					fmt.Fprintln(w, sha_b64+trip_modt+trip_size+" :"+trip_name)
				}
				fmt.Println("  New: " + trip_name)
				nnew++

				trip_name, trip_modt, trip_size = getNextTriplex(fileQueue)
				if trip_name == "" {
					///fmt.Println("[break2!]")
					break
				}
			} // fall out of this for when trip_name >= ssf_name
		}

		// 3. If we are at a matching name, we need to determine if a re-hash is required
		///fmt.Println("3: " + trip_name + " == " + ssf_name)
		if trip_name == ssf_name {
			///fmt.Println("match:", ssf_modtime, trip_modt, ssf_length, trip_size, !cli_rehash)
			if ssf_modtime == trip_modt && ssf_length == trip_size && !cli_rehash {
				// no change - pass through
				///fmt.Println("no change")
				if amWriting {
					fmt.Fprintln(w, s)
				}
			} else {
				// has changed
				///fmt.Println("has change")
				_, sha_b64 := getFileSha256(ssf_name)
				if amWriting {
					fmt.Fprintln(w, sha_b64+trip_modt+trip_size+" :"+trip_name)
				}

				msg := ""
				if ssf_modtime != trip_modt {
					msg += " Time"
				}
				if ssf_length != trip_size {
					msg += " Size"
				}
				if ssf_shab64 != sha_b64 {
					msg += " Hash"
				}
				if msg != "" {
					fmt.Println("  Chg: " + ssf_name + "  [" + msg + " ]")
					nchg++
				}
			}
			tf++
			tb += ssf_bytes

			trip_name, trip_modt, trip_size = getNextTriplex(fileQueue)
			continue
		}

		// 4. The file stream is before current
		///fmt.Println("4: " + trip_name + " < " + ssf_name)
		if trip_name > ssf_name {
			fmt.Println("  Del: " + ssf_name)
			ndel++
		}
	}

	// Input file exhausted - check fro more in the triplex channel
	trip_name, trip_modt, trip_size = getNextTriplex(fileQueue)
	///fmt.Println("t=", trip_name)
	for trip_name != "" {
		///fmt.Println("Need to add (from trip) [" + trip_name + "]")
		_, sha_b64 := getFileSha256(trip_name)
		///fmt.Println("(hash=" + sha_b64 + ")")
		if amWriting {
			fmt.Fprintln(w, sha_b64+trip_modt+trip_size+" :"+trip_name)
		}
		fmt.Println("  New: " + trip_name)
		nnew++

		trip_name, trip_modt, trip_size = getNextTriplex(fileQueue)
	}

	// Determine whether to keep existing file or replace
	nchanges := nnew + ndel + nchg
	//fmt.Print(nnew, ndel, nchg)
	switch nchanges {
	case 0:
		fmt.Println("Nothing added/deleted/changed - " + fn + " still good")
	case 1:
		fmt.Println("There was 1 change")
	default:
		fmt.Println("There were", nchanges, "changes")
	}

	// Optional totals and duplicates statements (and buffer flush)
	if amWriting {
		reportGrandTotals(w, tf, tb)
		reportDupes(w)
		w.Flush()

		if cli_overwrite {
			if nchanges > 0 {
				fmt.Println("Overwriting " + fn)
				os.Remove(fn)
				os.Rename(fnw, fn)
				os.Exit(1)
			} else if cli_grand || cli_dupes {
				fmt.Println("Ignoring --grand-total and --dupes in order to retain file timestamp")
			}
		}
	}

	os.Exit(0) //explicit (because we're a rc=0 or rc=1 depending on whether any changes)
}
