/*
Copyright © 2025 Jon Knox <jon@k2x.io>
*/
package cmd

import (
	"fmt"
	"log/slog"
	"os"
	"runtime"

	"github.com/spf13/cobra"
)

var test2Cmd = &cobra.Command{
	Use:   "test2",
	Short: "This is used to test different file-system and SSF access interfaces",
	Long: `This is used to test different file-system and SSF access interfaces.
Not intended for functional use.`,
	Aliases: []string{"test2", "t2"},
	Run: func(cmd *cobra.Command, args []string) {
		t2(args)
	},
}

func init() {
	rootCmd.AddCommand(test2Cmd)

	test2Cmd.Flags().StringVarP(&cli_path, "path", "p", "", "Path to directory to scan (default is current directory)")
	test2Cmd.Flags().BoolVarP(&cli_nodot, "no-dot", "", false, "Do not include files/directories beginning '.'")
}

// ----------------------- Test2 function below this line -----------------------

// Example:
// sm t2 input.ssf
// sm t2 input.ssf output.ssf
// sm t2 input.ssf output.ssf -p ./Desktop/

func t2(args []string) {
	var fnr string // filename for reading

	fmt.Println("\nPRE")
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

	// STAGE 1 - do path pre-scan
	fmt.Println("\nSTAGE 1 - PATH")
	proc := new(processSSF)
	err1 := proc.path(cli_path, cli_nodot)
	if err1 != nil {
		abort(1, fmt.Sprintf("Path %s not found", cli_path))
	}
	ptf, pts, err2 := proc.psize()
	if err2 != nil {
		abort(1, fmt.Sprintf("Cannot read path %s", cli_path))
	}
	fmt.Printf("Detected:  %10s files %20s bytes\n", intAsStringWithCommas(ptf), intAsStringWithCommas(pts))

	// STAGE 2 - do file pre-scan twice (using reset())
	// create scanner from fnr (fails if file cannot be opened, missing or has permissions errors)
	fmt.Println("\nSTAGE 2 - FILE")
	fnr = files[0]
	err3 := proc.fread(fnr, cli_nodot)
	if err3 != nil {
		abort(1, fmt.Sprintf("File %s not found", fnr))
	}
	ftf, ftd, fts, err4 := proc.fsize()
	if err4 != nil {
		abort(1, fmt.Sprintf("Error reading file %s", fnr))
	}
	fmt.Printf("Files:     %10s files %20s bytes", intAsStringWithCommas(ftf), intAsStringWithCommas(fts))
	if ftd > 0 {
		fmt.Printf("    (%s dropped)\n", intAsStringWithCommas(ftd))
	}
	fmt.Printf("\n")

	proc.close()
	os.Exit(0)
}
