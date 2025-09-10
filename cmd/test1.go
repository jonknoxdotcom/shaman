/*
Copyright © 2025 Jon Knox <jon@k2x.io>
*/
package cmd

import (
	"fmt"
	"log/slog"
	"os"
	"runtime"
	"time"

	"github.com/spf13/cobra"
)

// anonymiseCmd represents the anonymise command
var testCmd = &cobra.Command{
	Use:   "test",
	Short: "This is used to test different file-system and SSF access interfaces",
	Long: `This is used to test different file-system and SSF access interfaces.
Not intended for functional use.`,
	Aliases: []string{"test", "t1"},
	Run: func(cmd *cobra.Command, args []string) {
		tes(args)
	},
}

func init() {
	rootCmd.AddCommand(testCmd)

	testCmd.Flags().BoolVarP(&cli_verbose, "verbose", "v", false, "Give running commentary of anonymisation")
	testCmd.Flags().IntVarP(&cli_format, "format", "f", 1, "Format/anonymisation level 1..4")
	testCmd.Flags().BoolVarP(&cli_noempty, "no-empty", "", false, "Do not allow hash for empty file to appear")
	testCmd.Flags().IntVarP(&cli_chaff, "chaff", "", 0, "Chaff volume - approx number of records to add (default 0 = off)")
}

// ----------------------- Test function below this line -----------------------

func tes(args []string) {
	var fnr string // filename for reading

	fmt.Println("number of cpus is", runtime.NumCPU())

	// process CLI
	num, files, found := getSSFs(args)
	slog.Debug("cli handler", "num", num, "files", files, "found", found)
	switch true {
	case num > 2:
		abort(8, "Too many .ssf files - expected input, output (optional), exclusions (optional)")
	case num < 1:
		abort(9, "Input file not specified")
	case !found[0]:
		abort(6, "SSF file '"+files[0]+"' does not exist")
	case num > 1 && found[1]:
		fmt.Println("Warning: output file '" + files[1] + "' will be overwritten")
	}

	// create scanner from fnr (fails if file cannot be opened, missing or has permissions errors)
	fnr = files[0]
	scan := new(readSSF)
	if scan.open(fnr) != nil {
		abort(4, "Internal error #4: ")
	}
	defer scan.close()

	// Loop
	var shaMap = map[string]string{} // SHA to hex data (or empty string) -- just using b64 string for time being *FIXME*
	var shab64 string
	var err error // error object
	var errorTolerance int = 5
	var lineno int64 // needed for error reporting on .ssf file corruptions

	timeStart := time.Now()
	fmt.Println("rshaBase64, rformat, rtime, rbytes, rname, annovec")
	for true {
		// perform minimal fetch, err for bad files, no err + empty sha means exhaustion
		shab64, _, lineno, err = scan.nextSHA() // shab64, format, lineNumber, line, err

		// golden path - store lines and go again
		if shab64 != "" {
			// store presence (or more) here
			shaMap[shab64] = ""

			// TEST CODE
			rshaBase64, rformat, rtime, rbytes, rname, annovec, err := scan.allFields()
			fmt.Println(lineno, ":", rshaBase64, rformat, rtime, rbytes, rname, annovec, err)
			continue
		}

		// infrequent - allow a small number of misformed lines before giving up
		if err != nil {
			errorTolerance--
			if errorTolerance >= 0 {
				// temp addition of 's'
				fmt.Printf("Error: ignoring line %d of %s - %s\n", lineno, fnr, err)
				continue
			} else {
				abort(1, "Too many errors in "+fnr+" - giving up")
			}
		}

		// infrequent - eof detect
		if shab64 == "" {
			break
		}
	}
	timeTaken := time.Since(timeStart)
	timeus := int64(time.Since(timeStart) * 1000000 / time.Second)
	lps := 1000000 * lineno / timeus
	slog.Debug("Test read", "file", fnr, "lines", lineno, "shas", len(shaMap), "elapsedus", int(timeTaken/1000000), "lps", lps)

	// Is there anything to do?
	if len(shaMap) == 0 {
		abort(1, "Map is empty")
	} else {
		conditionalMessage(cli_verbose, fmt.Sprintf("Found %d records", len(shaMap)))
	}

	os.Exit(0) //explicit (because we're an rc=0 or rc=1 depending on whether any changes)
}
