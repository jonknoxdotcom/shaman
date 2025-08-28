/*
Copyright © 2025 Jon Knox <jon@k2x.io>
*/
package cmd

import (
	"bufio"
	"encoding/base64"
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

func isBase64(s string) bool {
	_, err := base64.StdEncoding.DecodeString(s + "=")
	return err == nil
}

// isHexadecimal returns validation of likely hexadecimal number that can be odd or even nybbles long.
// *FIXME* possible refactor the loop logic
func isHexadecimal(s string) bool {
	// fmt.Println("hex:", s)
	for i := 0; i < len(s); i++ {
		ch := s[i : i+1]
		if !strings.Contains("0123456789abcdef", ch) {
			return false
		}
	}
	return true
}

const NODATE = "-no dates-"
const NOSIZE = "-not known-"

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

	// Calculate longest filename (for reporting), and issue missing file rejections
	longestFileName := 0
	for i := range num {
		if !found[i] {
			fmt.Printf("File '%s' not found\n", files[i])
			continue
		}
		if len(files[i]) > longestFileName {
			longestFileName = len(files[i])
		}
	}

	// Walk through file list
	var numFiles int64
	var numBytes int64
	for i := range num {
		if !found[i] {
			// dead files reported earlier
			continue
		}

		format := -1
		numFiles = 0
		numBytes = 0
		dateStart := "ffffffff"
		dateEnd := "00000000"

		var r *os.File
		r, err := os.Open(files[i])
		if err != nil {
			slog.Debug("file reject", "fn", files[i], "reason", "permissions")
			fmt.Printf("File %s: cannot be read (check permissions)\n", files[i])
			continue
		}
		defer r.Close()

		lineno := 0 // local file line number
		validSSF := true
		scanner := bufio.NewScanner(r)
	SCANNER:
		for scanner.Scan() {
			// process the line from scanner (from the SSF file)
			s := scanner.Text()
			lineno++

			// drop comments or empty lines or too-short lines
			if len(s) == 0 || s[0:1] == "#" {
				// legitimate non-SHA lines in SSF format (continue scanner loop)
				continue
			}

			// check for minimum length line
			if len(s) < 43 {
				// cannot be SHA hash, so not SSF format
				slog.Debug("file reject", "fn", files[i], "reason", "short line", "line", lineno)
				validSSF = false
				break
			}

			// try to determine format:
			//  0 = default (5)
			//  1 = S		43
			//  2 = SM		43 + 8
			//  3 = SMB--	43 + 8 + 4/5/6/7/8/9
			//  4 = SMB-N	) have
			//  5 = SMBAN	) seps

			shaString := ""
			modTimeString := ""
			bytesString := ""

			// space separator?
			pos := strings.IndexByte(s, 32)
			slog.Debug("TEST", "fn", files[i], "line", lineno, "pos", pos)

			switch true {

			case pos == -1:
				format = 1
				shaString = s[0:43]
				if len(s) > 43+8 {
					format = 2
					modTimeString = s[43:51]
				}
				if len(s) > 43+8+4 {
					format = 3
					bytesString = s[51:]
				}

			case pos == 43:
				// is multipart line, with no modtime or bytes (??)
				format = 5
				shaString = s[0:43]

			case pos == 51:
				// is multipart line, with SHA+modtime, no bytes (??)
				format = 5
				shaString = s[0:43]
				modTimeString = s[43:51]

			case pos >= 55:
				// is multipart line, with SHA, modtime, bytes
				format = 5
				shaString = s[0:43]
				modTimeString = s[43:51]
				bytesString = s[51:pos]

			default:
				slog.Debug("file reject", "fn", files[i], "reason", "invalid format", "line", lineno)
				validSSF = false
				break SCANNER
			}

			// check values for correctness
			if !isBase64(shaString) {
				// has chars outside of b64 encoding tokens
				slog.Debug("file reject", "fn", files[i], "reason", "non-base64 SHA tokens", "line", lineno)
				validSSF = false
				break SCANNER
			}
			if modTimeString != "" && !isHexadecimal(modTimeString) {
				// has chars outside of 0-9, a-f
				slog.Debug("file reject", "fn", files[i], "reason", "non-hex modtime tokens", "line", lineno)
				validSSF = false
				break SCANNER
			}
			if bytesString != "" && !isHexadecimal(bytesString) {
				// has chars outside of 0-9, a-f
				slog.Debug("file reject", "fn", files[i], "reason", "non-hex bytes tokens", "line", lineno)
				validSSF = false
				break SCANNER
			}

			// apply tracking values
			if modTimeString != "" {
				// fmt.Println("this date:", modTimeString)
				if modTimeString < dateStart {
					dateStart = modTimeString
				}
				if modTimeString > dateEnd {
					dateEnd = modTimeString
				}
			}
			// fmt.Printf("b='%s'\n", bytesString)
			if bytesString != "" {
				n, _ := strconv.ParseInt(bytesString, 16, 64)
				// fmt.Println("b2=", n)
				numBytes += n
			}
			numFiles++
		}
		if !validSSF {
			fmt.Printf("File %s: invalid format\n", files[i])
			continue
		}

		// create date ranges
		slog.Debug("valid file", "fn", files[i], "format", format, "numFiles", numFiles, "numBytes", numBytes, "dateStart", dateStart, "dateEnd", dateEnd)
		dateStartStr := NODATE
		dateEndStr := NODATE
		if dateStart != "ffffffff" {
			var i int64
			var t time.Time

			i, _ = strconv.ParseInt(dateStart, 16, 64)
			t = time.Unix(i, 0)
			dateStartStr = t.Format(time.RFC3339)[0:10]

			i, _ = strconv.ParseInt(dateEnd, 16, 64)
			t = time.Unix(i, 0)
			dateEndStr = t.Format(time.RFC3339)[0:10]
		}

		// print summary of this file
		fmt.Printf("%-"+strconv.Itoa(longestFileName)+"s  ", files[i])
		fmt.Printf("%9sx  ", intAsStringWithCommas(numFiles))

		if format == 5 {
			fmt.Printf("%10s  %10s", dateStartStr, dateEndStr)
			fmt.Printf("%19s", intAsStringWithCommas(numBytes))
		}
		fmt.Println()
	}
}
