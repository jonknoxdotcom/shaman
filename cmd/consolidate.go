/*
Copyright © 2025 Jon Knox <jon@k2x.io>
*/
package cmd

import (
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

	generateCmd.Flags().IntVarP(&cli_format, "format", "f", 5, "Format/anonymisation level 0..5")
	consolidateCmd.Flags().BoolVarP(&cli_overwrite, "overwrite", "o", false, "Overwrite input file")
}

// ----------------------- Consolidate function below this line -----------------------

func con(args []string) {
	num, _, _ := getSSFs(args)
	if num > 1 {
		abort(8, "Too many .ssf files specified)")
	}

	// Read and write filenames
	var fnr string = ""
	var fnw string = ""

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
	case cli_format == 0:
		abort(6, "Cannot consolidate using sha256sum format")
	case cli_format > 3:
		abort(6, "Cannot use format with filename still present")

	// informational
	case num == 1 && !cli_overwrite:
		fnr = files[0]
		fmt.Println("Output will be to the screen")
	case num == 1 && cli_overwrite:
		fnr = files[0]
		fnw = fnr + ".temp"
		fmt.Println("File " + fnr + " will be be overwritten")
	case num == 2 && found[1]:
		fnw = files[1]
		fmt.Println("Output SSF file '" + files[1] + "' will be overwritten")
	}

	fmt.Println("fnr=", fnr)
	fmt.Println("fnw=", fnw)

	// collect with SHA as key and value as empty string, mod-time, or composite time/size
	var overlap = map[string]string{} // scoreboard for smaller collection
	shas, rows := ssfCollectRead(fnr, overlap, cli_format)
	slog.Debug("read smaller to get uniq shas", "file", fnr, "records", rows, "uniques", shas)

}
