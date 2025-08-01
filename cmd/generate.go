/*
Copyright © 2025 Jon Knox <jon@k2x.io>
*/
package cmd

import (
	"github.com/spf13/cobra"

	"bufio"
	b64 "encoding/base64"
	"fmt"
	"os"
)

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
	generateCmd.Flags().BoolVarP(&cli_totals, "totals", "t", false, "Display count of bytes and files on completion")
}

// ----------------------- Generate function below this line -----------------------

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
		// sha generation and trimming
		sha_bin, _ := getSha256OfFile(filerec.filename)
		sha_b64 := b64.StdEncoding.EncodeToString(sha_bin)
		if len(sha_b64) != 44 || sha_b64[43:] != "=" {
			// can't happen
			abort(3, "sha result error for "+filerec.filename)
		}
		sha_b64 = sha_b64[0:43]
		if cli_dupes {
			dupes[sha_b64] = dupes[sha_b64] + 1
		}
		total_bytes += filerec.size
		total_files++

		// output stage
		outbuf := sha_b64
		if !cli_anon {
			outbuf += fmt.Sprintf("%x%04x :%s", filerec.modified, filerec.size, filerec.filename)
		}
		fmt.Fprintln(w, outbuf)
	}

	// Optional totals and duplicates statements
	reportTotals(w, total_files, total_bytes)
	reportDupes(w)

	w.Flush()
}
