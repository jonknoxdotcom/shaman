/*
Copyright © 2025 Jon Knox <jon@k2x.io>
*/
package cmd

import (
	"log/slog"

	"github.com/spf13/cobra"

	"fmt"
)

// -------------------------------- Cobra management -------------------------------

// generateCmd represents the generate command
var misnamedCmd = &cobra.Command{
	Use:   "misnamed",
	Short: "Search for misnamed files",
	Long: `shaman generate
Search for misnamed files either in an SSF file or the current directory or nominated path.
A misnamed file is one which accidentally or intentionally contains non-printable ASCII characters.`,
	Aliases: []string{"mis"},
	Args:    cobra.MaximumNArgs(1),
	GroupID: "G1",
	Run: func(cmd *cobra.Command, args []string) {
		mis(args)
	},
}

func init() {
	rootCmd.AddCommand(misnamedCmd)

	misnamedCmd.Flags().StringVarP(&cli_path, "path", "p", "", "Path to directory to scan (default is current directory)")
	misnamedCmd.Flags().BoolVarP(&cli_verbose, "verbose", "v", false, "Give running commentary of update")
	misnamedCmd.Flags().BoolVarP(&cli_nodot, "no-dot", "", false, "Do not include files/directories beginning '.'")
}

// ----------------------- Misnamed function below this line -----------------------

func mis(args []string) {

	// process CLI
	num, files, found := getSSFs(args)
	slog.Debug("cli handler", "num", num, "files", files, "found", found)
	switch true {
	case num == 0:
		// direct to stdout - switch off all updates
		// cli_verbose = false
	case num > 99:
		abort(8, "Too many .ssf files specified)")
	case num == 1 && !found[0]:
		abort(6, "File not found: '"+files[0]+"'")
	}

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

	// process file list to generate SSF records
	var total_files int64
	var error_files int64
	for filerec := range fileQueue {

		escaped := storeLine(filerec.filename)
		if escaped != filerec.filename {
			fmt.Printf("%s\n%s\n\n", filerec.filename, escaped)
			error_files++
		}
		total_files++
	}

	if cli_verbose {
		fmt.Printf("Total: %s files, of which %s suspicious\n", intAsStringWithCommas(total_files), intAsStringWithCommas(error_files))
	}

}
