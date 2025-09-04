/*
Copyright © 2025 Jon Knox <jon@k2x.io>
*/
package cmd

import (
	"bufio"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"os"
	"slices"
	"strings"

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
	Aliases: []string{"ano", "anonymize"},
	Run: func(cmd *cobra.Command, args []string) {
		ano(args)
	},
}

func init() {
	rootCmd.AddCommand(anonymiseCmd)

	anonymiseCmd.Flags().StringVarP(&cli_path, "path", "p", "", "Path to directory to scan (default is current directory)")
	anonymiseCmd.Flags().IntVarP(&cli_format, "format", "f", 1, "Format/anonymisation level 1..5 (default: 1)")
	anonymiseCmd.Flags().BoolVarP(&cli_verbose, "verbose", "v", false, "Give running commentary of anonymisation")
	anonymiseCmd.Flags().BoolVarP(&cli_nodot, "no-dot", "", false, "Drop any files/directories beginning '.' if found in the source")
	anonymiseCmd.Flags().BoolVarP(&cli_noempty, "no-empty", "", false, "Do not allow hash for empty file to appear")
	anonymiseCmd.Flags().IntVarP(&cli_chaff, "chaff", "", 0, "Chaff volume - approx number of records to add (default: 0 = off)")
}

// ----------------------- Reader module -----------------------

// nextLineMinimal takes a scanner file and returns the next record's SHA + undecoded line. It also tracks line number.
// The returned line will have valid base64 and hex (if present) in all the right places. It may be format 1,2,3,4,5.
// The tracking line number is always returned, and can be relied upon and quoted in an error message if required.
// This routine is optimised to fail quickly if fed a file that is not SSF.
func nextLineMinimal(scanner *bufio.Scanner, trackingLine int64) (newTrackingLine int64, shab64 string, format int, line string, err error) {
	for scanner.Scan() {
		// process the line from scanner (from the SSF file)
		s := scanner.Text()
		trackingLine++
		// fmt.Printf("[nLM reads] %d: [%s]\n", trackingLine, s)

		// drop comments or empty lines
		if len(s) == 0 || s[0:1] == "#" {
			continue
		}

		// check for sufficient line to check for SHA / validate SHA characters
		if len(s) < 43 || !isBase64(s[0:43]) {
			// must be a bad line - too short or not right characters (caller likely to abort read)
			return trackingLine, "", -1, s, errors.New("invalid format #1")
		}

		// just the hash is fine
		if len(s) == 43 {
			// format 1: just SHA
			return trackingLine, s[0:43], 1, s, nil
		}

		// rest of initial field should be hex
		pos := strings.IndexByte(s, 32)
		if pos == -1 {
			// there's no annotation or name
			hexStream := s[43:]
			if !isHexadecimal(hexStream) {
				return trackingLine, "", -1, s, errors.New("invalid format #2")
			}
			if len(hexStream) == 8 {
				// format 2: just SHA+modtime
				return trackingLine, s[0:43], 2, s, nil
			}
			if len(hexStream) >= 12 && len(hexStream) <= 22 {
				// format 3: just SHA+modtime+size
				return trackingLine, s[0:43], 3, s, nil
			}
			return trackingLine, "", -1, s, errors.New("invalid format #3")
		} else {
			// there's a space after the presumed hex
			hexStream := s[43:pos]
			// fmt.Println("[" + hexStream + "]")
			if len(hexStream) >= 12 && len(hexStream) <= 22 {
				// format 5: just SHA+modtime+size
				if s[pos+1:pos+2] == ":" {
					return trackingLine, s[0:43], 5, s, nil
				} else {
					return trackingLine, s[0:43], 4, s, nil
				}
			}
			return trackingLine, "", -1, s, errors.New("invalid format #4")
		}
	}

	// fall out (Scan failed) - give an empty string
	return trackingLine, "", -1, "", nil
}

// // extractSSFLine is meant to be called after nextLineMinimal if more than a valid hash is wanted.
// func extractSSFLine(s string) (shab64 string, modtime string, length string, name string, annotations string) {

// }

// ----------------------- Anonymise function below this line -----------------------

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
	switch num {
	case 1:
		// One file given
		fnw = ""
	case 2:
		// Two files given - from A to B
		fnw = files[1]
	default:
		// (should not happen)
		abort(3, "unexpected update")
	}

	// open writing buffer (if used)
	w = writeInit(fnw)
	// amWriting := (fnw != "")

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

	// Loop
	// var err error     // error object
	var shab64 string // sha
	// var format int    // format
	var s string     // line contents
	var lineno int64 // needed for error reporting on .ssf file corruptions
	var errorTolerance int = 5
	var shaMap = map[string]string{} // SHA to hex data (or empty string) -- just using b64 string for time being *FIXME*
	scanner := bufio.NewScanner(r)
	for true {
		// err, lineno, shab64, format, s = nextLineMinimal(scanner, lineno)
		lineno, shab64, _, s, err = nextLineMinimal(scanner, lineno)
		// fmt.Println(err, lineno, shab64, format, s)
		if err != nil {
			errorTolerance--
			if errorTolerance >= 0 {
				fmt.Printf("Error: ignoring - %s in %s at line %d\n", err, fnr, lineno)
				continue
			} else {
				abort(1, "Too many errors in "+fnr+" - giving up")
			}
		}
		if s == "" {
			break
		}
		shaMap[shab64] = ""

		// fmt.Fprintf(w, "received l=%d, f=%d, sha=%s, s=%s\n", lineno, format, shab64, s)
	}
	if len(shaMap) == 0 {
		abort(1, "Nothing found to anonymise")
	} else {
		fmt.Printf("Found %d records\n", len(shaMap))
	}

	// Chaffing
	if cli_chaff > 0 {
		fmt.Printf("Adding %d chaff records\n", cli_chaff)
	}

	// Sort the SHAs
	fmt.Printf("Sorting to deny position analysis\n")
	var ordered []string
	ordered = slices.Sorted(maps.Keys(shaMap))

	// Write out
	fmt.Printf("Writing %d record to output\n", len(shaMap))
	for _, k := range ordered {
		fmt.Fprintln(w, k+shaMap[k])
	}
	w.Flush()

	os.Exit(0) //explicit (because we're a rc=0 or rc=1 depending on whether any changes)
}
