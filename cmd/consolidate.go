/*
Copyright © 2025 Jon Knox <jon@k2x.io>
*/
package cmd

import (
	"bufio"
	"maps"
	"slices"

	"github.com/spf13/cobra"

	"fmt"
	"log/slog"
)

// -------------------------------- Cobra management -------------------------------

// consolidateCmd represents the consolidate command
var consolidateCmd = &cobra.Command{
	Use:   "consolidate",
	Short: "Combine entries of an anonymous or anonymous/modify files",
	Long: `shaman consolidate
De-duplicates an 'anonymous style' file to a format 1/2/3 result (one with SHA and optionally modify 
time and size). Output is sorted. Where modify times are present, consolidate outputs the earliest 
modify date. The resulting file is useful as a 'destroy-list', or a 're-patch origin dates' source.
Usage examples:
   shaman con input.ssf                           # writes to stdout
   shaman con file.ssf --overwrite                # overwrites file
   shaman con input.ssf output.ssf                # writes to new file (format 3 file)
   shaman con input.ssf output.ssf  -f 3          # same as above
   shaman con input.ssf output.ssf  -f 2          # write to format 2 (SHA + modify time)
   shaman con input.ssf output.ssf  -f 1          # write to format 1 (SHA only - max anonymised)
The actual output format will be the lowest or user specified over-ridden by format of input files.
When picking an earlier date, the year 1980 is considered to be the lowest valid limit.`,
	Aliases: []string{"con"},
	GroupID: "G3",

	Args: cobra.MaximumNArgs(99),
	Run: func(cmd *cobra.Command, args []string) {
		con(args)
	},
}

func init() {
	rootCmd.AddCommand(consolidateCmd)

	consolidateCmd.Flags().IntVarP(&cli_format, "format", "f", 0, "Format/anonymisation level 1..3")
	consolidateCmd.Flags().BoolVarP(&cli_overwrite, "overwrite", "o", false, "Overwrite input file")
}

// ----------------------- Consolidate function below this line -----------------------

func con(args []string) {
	var w *bufio.Writer // write buffer
	var fnr string = "" // read filename
	var fnw string = "" // write filename
	var form int = 3    // format: default is 3 (SHA+modtime+size)

	if cli_format != 0 {
		form = cli_format
	}

	slog.Debug("cons - prep", "cli_format", cli_format, "form", form)

	// Make sure we have a single input file that exists / error appropriately
	num, files, found := getSSFs(args)
	slog.Debug("cli handler", "num", num, "files", files, "found", found)
	switch true {
	// error based
	case num == 0:
		abort(8, "Need at least one input file")
	case num > 2:
		abort(8, "Too many .ssf files specified - expected one or two")
	case !found[0]:
		abort(6, "Input SSF file '"+files[0]+"' does not exist")
	case form == 9:
		abort(6, "Cannot consolidate using sha256sum format")
	case form < 1 && form > 3:
		abort(6, fmt.Sprintf("Format %d invalid - consolidate only accepts formats 1, 2 and 3 (default)", form))

	// informational
	case num == 1 && !cli_overwrite:
		fnr = files[0]
		// fmt.Println("Output will be to the screen")
	case num == 1 && cli_overwrite:
		fnr = files[0]
		fnw = fnr + ".temp"
		fmt.Println("File " + fnr + " will be be overwritten")
	case num == 2 && found[1]:
		fnw = files[1]
		fmt.Println("Output SSF file '" + files[1] + "' will be overwritten")
	}

	// fmt.Println("fnr=", fnr)
	// fmt.Println("fnw=", fnw)

	// open writer (stdout or file)
	w = writeInit(fnw)

	// collect with SHA as key and value as empty string, mod-time, or composite time/size
	var hits = map[string]string{} // scoreboard for smaller collection
	shas, rows := ssfCollectRead(fnr, hits, form)
	slog.Debug("ssfCollectRead", "file", fnr, "records", rows, "uniques", shas)

	// write in key order
	ordered := slices.Sorted(maps.Keys(hits))
	for _, k := range ordered {
		fmt.Fprintln(w, k+hits[k])
	}
	w.Flush()
}
