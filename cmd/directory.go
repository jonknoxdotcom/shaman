/*
Copyright © 2025 Jon Knox <jon@k2x.io>
*/
package cmd

import (
	"bufio"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// infoCmd represents the info command
var directoryCmd = &cobra.Command{
	Use:   "directory",
	Short: "Basic information about SSF file(s)",
	Long: `Produces a one-line summary of file in terms of number of files, total
	bytes found, from/to dates.  Can determine format or reject files. 
	Results list sorted by filename.
	Works with up to 99 files - e.g. use 'shaman dir *.ssf *.temp'.
	Can use '--show-format' to see what format shaman believes a file is.`,

	Aliases: []string{"dir"},
	Args:    cobra.MaximumNArgs(200),
	GroupID: "G1",
	Run: func(cmd *cobra.Command, args []string) {
		dir(args)
	},
}

func init() {
	rootCmd.AddCommand(directoryCmd)

	directoryCmd.Flags().BoolVarP(&cli_showform, "show-format", "", false, "Show file's determined format")
}

// ----------------------- Directory function below this line -----------------------

func dir(args []string) {
	// Process CLI and perform sanity checks
	num, files, found := getAnySort(args)
	slog.Debug("cli handler", "num", num, "files", files, "found", found)
	switch true {
	case num > 99:
		abort(8, "Too many signature files")
	case num < 1:
		abort(9, "You need to give at least one file")
	}

	// Walk through file list
	var numFiles int64
	var numBytes int64
	for i := range num {

		if !found[i] {
			fmt.Printf("Signature file '%s' not found\n", files[i])
			continue
		}

		numFiles = 0
		numBytes = 0
		dateStart := "ffffffff"
		dateEnd := "00000000"
		isAnon := false

		var r *os.File
		r, err := os.Open(files[i])
		if err != nil {
			fmt.Printf("File %s: cannot be read (check permissions)\n", files[i])
			continue
		}
		defer r.Close()

		lineno := 0 // local file line number
		scanner := bufio.NewScanner(r)
		for scanner.Scan() {
			// process the line from scanner (from the SSF file)
			s := scanner.Text()
			lineno++

			// drop comments or empty lines or too-short lines
			if len(s) == 0 || s[0:1] == "#" {
				continue
			}

			// formats:
			// 0 = default (5)
			// 1 = S
			// 2 = SM
			// 3 = SMB--
			// 4 = SMB-N
			// 5 = SMBAN

			// work out if likely to be signature
			pos := strings.IndexByte(s, 32)

			if pos == -1 && len(s) == 43 {
				// looks like format 0
				isAnon = true
			} else {

				if pos < 43 { // not enough for a Base64 SHA256 - assume not SSF
					fmt.Printf("Ignoring %s (line %d invalid)\n", files[i], lineno)
					break
				}

				if pos == -1 || pos < 55 {
					fmt.Printf("Ignoring %s (line %d invalid)\n", files[i], lineno)
					break
				}
			}
			numFiles++
		}

		// create date ranges
		dateStartStr := "????-??-??"
		dateEndStr := "????-??-??"
		if dateStart != "ffffffff" {
			var i int64
			var t time.Time

			i, _ = strconv.ParseInt(dateStart, 16, 64)
			t = time.Unix(i, 0)
			dateStartStr = t.Format("YYYYMMDD")

			i, _ = strconv.ParseInt(dateEnd, 16, 64)
			t = time.Unix(i, 0)
			dateEndStr = t.Format("YYYYMMDD")
		}

		// print summary of this file
		if !isAnon {
			fmt.Printf("%18s  %10s - %10s%9sx",
				intAsStringWithCommas(numBytes),
				dateStartStr, dateEndStr,
				intAsStringWithCommas(numFiles))
		} else {
			fmt.Printf("%18s  %10s - %10s%9sx",
				"------------------",
				dateStartStr, dateEndStr,
				intAsStringWithCommas(numFiles))
		}

		if cli_showform {
			fmt.Printf("  5/SMBAN")
		}

		fmt.Printf("  %s\n", files[i])
	}
}
