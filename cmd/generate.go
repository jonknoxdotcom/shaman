/*
Copyright © 2025 Jon Knox <jon@k2x.io>
*/
package cmd

import (
	"github.com/spf13/cobra"

	"bufio"
	"fmt"
	"os"
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
	Run: func(cmd *cobra.Command, args []string) {
		gen(args)
	},
}

func init() {
	rootCmd.AddCommand(generateCmd)

	generateCmd.Flags().StringVarP(&cli_path, "path", "p", "", "Path to directory to scan (default is current directory)")
	generateCmd.Flags().BoolVarP(&cli_anon, "anonymous", "a", false, "Whether to mask the SSF output (to include only hashes)")
	generateCmd.Flags().BoolVarP(&cli_dupes, "dupes", "d", false, "Whether to show dupes (as comments) on completion")
	generateCmd.Flags().BoolVarP(&cli_grand, "grand-totals", "g", false, "Display grand totals of bytes/files on completion")

}

// ----------------------- Generate function below this line -----------------------

// Rate: 167 files per sec (10k/min) for Desktop on MBP A2141

func gen(args []string) {
	num, files, found := getSSFs(args)
	if num > 1 {
		abort(8, "Too many .ssf files specified)")
	}

	// Check whether file specified and if so that it does not yet exist and that it ends ".ssf"
	var w *bufio.Writer
	if num == 1 {
		// check not already existing
		fn := files[0]
		if found[0] {
			abort(6, "Output file '"+fn+"' already exists")
		}

		// open for writing (on 'w' writer handle)
		file_out, err := os.Create(fn)
		if err != nil {
			abort(4, "Surprisingly, unable to create file "+fn)
		}
		defer file_out.Close()
		//w = bufio.NewWriter(file_out)
		w = bufio.NewWriterSize(file_out, 64*1024*1024) // whopping
	} else {
		// no file given, so use stdout
		w = bufio.NewWriterSize(os.Stdout, 500) // more 'real time'
	}

	// Get the encoding path
	var startpath string = "."
	if cli_path != "" {
		startpath = cli_path // add validation here
	}

	// ------------------------------------------

	// Call the tree walker to generate a file list (as a channel)
	fileQueue := make(chan triplex, 4096)
	go func() {
		defer close(fileQueue)
		walkTreeToChannel(startpath, fileQueue)
	}()

	// process file list to generate SSF records
	var total_files int64
	var total_bytes int64
	for filerec := range fileQueue {
		_, sha_b64 := getFileSha256(filerec.filename)

		outbuf := sha_b64
		if !cli_anon {
			outbuf += fmt.Sprintf("%x%04x :%s", filerec.modified, filerec.size, filerec.filename)
		}
		fmt.Fprintln(w, outbuf)

		if cli_dupes {
			dupes[sha_b64] = dupes[sha_b64] + 1
		}
		total_bytes += filerec.size
		total_files++
	}

	// Optional totals and duplicates statements
	reportGrandTotals(w, total_files, total_bytes)
	reportDupes(w)

	w.Flush()
}
