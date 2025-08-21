/*
Copyright © 2025 Jon Knox <jon@k2x.io>
*/
package cmd

import (
	"log/slog"

	"github.com/spf13/cobra"

	"bufio"
	"fmt"
)

// -------------------------------- Cobra management -------------------------------

// generateCmd represents the generate command
var generateCmd = &cobra.Command{
	Use:   "generate [file.ssf]",
	Short: "Generate a sha-manager signature format (.ssf) file",
	Long: `shaman generate
Generate a sha-manager format (.ssf) file from specified directory (or current directory if none specified), 
writing the output to a named file (or stdout if none given)`,
	Aliases: []string{"gen"},
	Args:    cobra.MaximumNArgs(1),
	GroupID: "G1",
	Run: func(cmd *cobra.Command, args []string) {
		gen(args)
	},
}

func init() {
	rootCmd.AddCommand(generateCmd)

	generateCmd.Flags().StringVarP(&cli_path, "path", "p", "", "Path to directory to scan (default is current directory)")
	generateCmd.Flags().IntVarP(&cli_format, "format", "f", 0, "Format/anonymisation level 1..5 or 9")
	generateCmd.Flags().BoolVarP(&cli_dupes, "dupes", "d", false, "Whether to show dupes (as comments) on completion")
	generateCmd.Flags().BoolVarP(&cli_grand, "grand-totals", "g", false, "Display grand totals of bytes/files on completion")
	generateCmd.Flags().BoolVarP(&cli_verbose, "verbose", "v", false, "Give running commentary of update")
	generateCmd.Flags().BoolVarP(&cli_nodot, "no-dot", "", false, "Do not include files/directories beginning '.'")
}

// ----------------------- Generate function below this line -----------------------

// Rate: 167 files per sec (10k/min) for Desktop on MBP A2141

func gen(args []string) {
	var w *bufio.Writer
	var fn string = "" // Output file (for "" for stdout)
	var ticker bool = true
	var form int = 5 // format defaults to 5

	// for update, the format default is 5 (full)
	if cli_format != 0 {
		form = cli_format
	}
	// process CLI
	num, files, found := getSSFs(args)
	slog.Debug("cli handler", "num", num, "files", files, "found", found)
	switch true {
	case num == 0:
		// direct to stdout - switch off all updates
		ticker = false // no dots if writing to stdout
		cli_verbose = false
	case num > 2:
		abort(8, "Too many .ssf files specified)")
	case num == 1 && !found[0]:
		fn = files[0]
		ticker = false
	case num == 1 && found[0]:
		abort(6, "Output file '"+files[0]+"' already exists")
	}

	// find ends .ssf??

	// open writer (stdout or file)
	w = writeInit(fn)

	// Call the tree walker to generate a file list (as a channel)
	var startpath string = "."
	if cli_path != "" {
		startpath = cli_path // add validation here
	}
	fileQueue := make(chan triplex, 4096)
	go func() {
		defer close(fileQueue)
		walkTreeYieldFilesToChannel(startpath, fileQueue, cli_nodot)
	}()

	var verbosity int = 1
	if cli_verbose {
		fmt.Println("Generating:")
		verbosity = 2
		ticker = false
	} else {
		if num == 1 {
			fmt.Print("Processing")
			ticker = true
		}
	}

	// process file list to generate SSF records
	var total_files int64
	var total_bytes int64
	for filerec := range fileQueue {
		// drop if files or directories begins "." and nodot asserted
		// if cli_nodot && (strings.Contains(filerec.filename, "/.") || filerec.filename[0:1] == ".") {
		// 	continue
		// }

		_, sha_b64, _ := getFileSha256(filerec.filename)

		modt := fmt.Sprintf("%8x", filerec.modified)
		size := fmt.Sprintf("%04x", filerec.size)
		writeRecord(w, true, form, verbosity, "N", sha_b64, modt, size, filerec.filename, "")

		// stats and ticks (dot every 100, flush every 500)
		total_bytes += filerec.size
		total_files++

		if ticker && total_files%100 == 0 {
			fmt.Print(".")
		}
	}
	w.Flush()

	if ticker {
		fmt.Println(".")
	}
	if cli_verbose {
		fmt.Printf("Total: %s files, %s bytes\n", intAsStringWithCommas(total_files), intAsStringWithCommas(total_bytes))
	}

}
