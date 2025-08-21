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

// sumCmd represents the sum command
var sumCmd = &cobra.Command{
	Use:   "sum [file.ssf]",
	Short: "Produce a GNU-style sha256sum check file from an SSF or live directory",
	Long: `shaman sum file.ssh
Generate a GNU-style sha256sum check file from an SSF or live directory.  Typically used with the --path
switch to select a subdirectory. Produces immediately from file, or can calculate live.`,
	Aliases: []string{"sum"},
	Args:    cobra.MaximumNArgs(1),
	GroupID: "G1",
	Run: func(cmd *cobra.Command, args []string) {
		sum(args)
	},
}

func init() {
	rootCmd.AddCommand(sumCmd)

	sumCmd.Flags().StringVarP(&cli_path, "path", "p", "", "Path to directory to use (default is all files)")
	sumCmd.Flags().BoolVarP(&cli_nodot, "no-dot", "", false, "Ignore files/directories beginning '.'")
}

// ----------------------- Sum function below this line -----------------------

// Usage:
// shaman exp file.ssf -t sha256sum -p bin/ --base
// shaman exp file.ssf -t tsv
// shaman exp file.ssf -t csv
// shaman exp file.ssf -t tsv --filter Y
// shaman exp file.ssf -t tsv --filter JGW
// shaman exp file.ssf subset.ssf  -p folder/ --base
// shaman exp file.ssf -t col -p bills/

// shaman imp file.ssf -t sha256sum

// jon@users-MacBook-Pro shaman % find * -name "*.go"  -type f | xargs sha256sum
// 86c204da589803f499481c7b2184d2761e3094eb2ae746273553238eba47f6ba  cmd/rename.go
// e5b82a8053748856bffe87fe6243fcc609939a7ea262d195da29972957079867  cmd/triplex.go
// c6cdb3d4acc1ef786c0d9ade585b2c9b14bbc7df16e217b4613dfd0a6f7867ac  cmd/generate.go
// 4926fc3e71abfe4e6f668c383ac1de88a0d1037b3dbbb5626d42aa513fd49ffa  cmd/whereis.go
// e546bba425f1c4b6acb119524c6c960b4b476f5b6df95400fb58e643b5e8fff9  cmd/duplicates.go

// find * -name "*.go"  -type f | xargs sha256sum > code.sha256
// jon@users-MacBook-Pro shaman % sha256sum -c code.sha256
// cmd/rename.go: OK
// cmd/triplex.go: OK
// cmd/generate.go: OK
// cmd/whereis.go: OK

func sum(args []string) {
	num, files, found := getSSFs(args)
	if num > 1 {
		abort(8, "Too many .ssf files specified)")
	}

	// Check whether file specified and if so that it does not yet exist and that it ends ".ssf"
	var w *bufio.Writer
	ticker := false
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
		ticker = true
		fmt.Printf("Generating (dot=100)")
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

	// Call the tree walker to sum a file list (as a channel)
	fileQueue := make(chan triplex, 4096)
	go func() {
		defer close(fileQueue)
		walkTreeYieldFilesToChannel(startpath, fileQueue, cli_nodot)
	}()

	// process file list to sum SSF records
	var total_files int64
	var total_bytes int64
	for filerec := range fileQueue {
		_, sha_b64, _ := getFileSha256(filerec.filename)
		fmt.Fprintln(w, sha_b64+" "+filerec.filename)

		// stats and ticks (dot every 100, flush every 500)
		total_bytes += filerec.size
		total_files++
		if ticker && total_files%100 == 0 {
			fmt.Print(".")
		}
		if total_files%500 == 0 {
			w.Flush()
		}
	}

	if ticker {
		fmt.Println(".")
	}

	// Optional totals and duplicates statements
	reportGrandTotals(w, total_files, total_bytes)
	reportDupes(w)

	w.Flush()
}
