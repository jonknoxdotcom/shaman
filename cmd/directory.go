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
		// dateStart := "ffffffff"
		// dateEnd := "00000000"
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

		// print summary of this file
		if !isAnon {
			fmt.Printf("%18s  %10s - %10s%9sx",
				intAsStringWithCommas(numBytes),
				"2010-xx-xx", "2025-xx-xx",
				intAsStringWithCommas(numFiles))
		} else {
			fmt.Printf("%18s  %10s - %10s%9sx",
				"------------------",
				"????-??-??", "????-??-??",
				intAsStringWithCommas(numFiles))
		}

		if cli_showform {
			fmt.Printf("  5/SMBAN")
		}

		fmt.Printf("  %s\n", files[i])
	}
}
