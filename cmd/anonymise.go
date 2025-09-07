/*
Copyright © 2025 Jon Knox <jon@k2x.io>
*/
package cmd

import (
	"bufio"
	"fmt"
	"log/slog"
	"maps"
	"os"
	"slices"
	"time"

	"github.com/spf13/cobra"
)

// anonymiseCmd represents the anonymise command
var anonymiseCmd = &cobra.Command{
	Use:   "anonymise",
	Short: "Produce a version of an SSF file stripped of everything except SHA hashes",
	Long: `Removes the filename, size and last used information from an .ssf file to leave only the hashes - useful
when you want to have a very small .ssf for the purposes of checking for the presence of files without wanting to 
disclose the filenames such as a list of customer names, account codes or other related personally-identifiable 
information (PII).  An .ssf with only hashes can still be used for comparisons and detections.`,
	Aliases: []string{"anonymize", "ano"},
	Run: func(cmd *cobra.Command, args []string) {
		ano(args)
	},
}

func init() {
	rootCmd.AddCommand(anonymiseCmd)

	anonymiseCmd.Flags().BoolVarP(&cli_verbose, "verbose", "v", false, "Give running commentary of anonymisation")
	anonymiseCmd.Flags().IntVarP(&cli_format, "format", "f", 1, "Format/anonymisation level 1..4")
	anonymiseCmd.Flags().BoolVarP(&cli_noempty, "no-empty", "", false, "Do not allow hash for empty file to appear")
	anonymiseCmd.Flags().IntVarP(&cli_chaff, "chaff", "", 0, "Chaff volume - approx number of records to add (default 0 = off)")
}

// ----------------------- Anonymise function below this line -----------------------

// CURRENT
// Example use:
// sm ano input.ssf 									# format 1 output, no chaff, output to stdout
// sm ano input.ssf anon.ssf							# format 1 output, no chaff
// sm ano input.ssf anon.ssf --no-empty 				# format 1 output, no chaff, drops empty record

// TARGET
// Example use:
// sm ano input.ssf 									# format 1 output, no chaff, output to stdout
// sm ano input.ssf anon.ssf							# format 1 output, no chaff
// sm ano input.ssf anon.ssf --no-empty 				# format 1 output, no chaff, drops empty record
// sm ano input.ssf anon.ssf --no-empty --no-dot		# format 1 output, no chaff, drops empty record, drops dot files
// sm ano input.ssf anon.ssf --chaff 100				# format 1, 80-120 chaff records
// sm ano input.ssf anon.ssf --format 2					# format 2 output, no chaff
// sm ano input.ssf anon.ssf --chaff 100 --format 2		# format 2 output, chaff includes random modtime
// sm ano input.ssf anon.ssf --chaff 100 --format 3		# format 3 output, chaff includes random modtime/size
// sm ano input.ssf anon.ssf --format 4					# format 4 output (includes annotations) - chaff not available
//
// Excluding codes:
// sm ano input.ssf anon.ssf exclude.ssf				# format 1 output, no chaff, SHAs in exclude.ssf dropped
// sm ano input.ssf anon.ssf exclude.ssf				# format 1 output, no chaff, SHAs in exclude.ssf dropped
//
// Not allowed:
// sm ano input.ssf anon.ssf --chaff 100 --format 4		# because --chaff can't make up annotations
// sm ano input.ssf anon.ssf --format 5					# because it wouldn't be anonymised

func ano(args []string) {
	var fnr string      // filename for reading
	var fnw string      // where to write to (filename to open)
	var w *bufio.Writer // buffer writer

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

	// create writer
	if num == 2 {
		fnw = files[1]
	}

	// Loop
	var shaMap = map[string]string{} // SHA to hex data (or empty string) -- just using b64 string for time being *FIXME*
	var shab64 string
	var err error // error object
	var errorTolerance int = 5
	var lineno int64 // needed for error reporting on .ssf file corruptions

	// var format int    // format

	timeStart := time.Now()
	for true {
		// perform minimal fetch, err for bad files, no err + empty sha means exhaustion
		shab64, _, lineno, err = scan.nextSHA() // shab64, format, lineNumber, line, err

		// golden path - store lines and go again
		if shab64 != "" {
			// store presence (or more) here
			shaMap[shab64] = ""
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
	slog.Debug("Anonymisation read", "file", fnr, "lines", lineno, "shas", len(shaMap), "elapsedus", int(timeTaken/1000000), "lps", lps)

	// Is there anything to do?
	if len(shaMap) == 0 {
		abort(1, "Nothing found to anonymise")
	} else {
		conditionalMessage(cli_verbose, fmt.Sprintf("Found %d records", len(shaMap)))
	}

	// Chaffing
	if cli_chaff > 0 {
		conditionalMessage(cli_verbose, fmt.Sprintf("Adding %d chaff records", cli_chaff))
		// chaff logic here once format levels have been fixed / for moment, message only
	}

	// Empty hash remover
	_, ok := shaMap[emptySHAb64]
	if cli_noempty {
		if ok {
			conditionalMessage(cli_verbose, "Removing the empty hash")
			delete(shaMap, emptySHAb64)
		} else {
			conditionalMessage(cli_verbose, "No empty hash found")
		}
	} else {
		if ok {
			conditionalMessage(cli_verbose, "Warning: the empty hash is present")
		}
	}

	// Sort the SHAs
	conditionalMessage(cli_verbose, "Sorting to deny position analysis")
	var ordered []string
	ordered = slices.Sorted(maps.Keys(shaMap))

	// Write out
	conditionalMessage(cli_verbose, fmt.Sprintf("Writing %d anonymised records", len(shaMap)))
	w = writeInit(fnw)
	for _, key := range ordered {
		fmt.Fprintln(w, key+shaMap[key])
	}
	w.Flush()

	// // Write binary version
	// fnwb := fnw + ".bin"
	// fb, berr := os.Create(fnwb)
	// if berr != nil {
	// 	abort(4, "Cannot create binary file "+fnwb)
	// }
	// var bin binsha
	// for _, j := range ordered {
	// 	bin = shaBase64ToShaBinary(j)
	// 	for i := 0; i < 32; i++ {
	// 		fb.Write(bin[i])
	// 	}
	// }

	os.Exit(0) //explicit (because we're an rc=0 or rc=1 depending on whether any changes)
}
