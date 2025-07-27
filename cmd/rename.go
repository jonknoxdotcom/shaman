/*
Copyright © 2025 Jon Knox <jon@k2x.io>
*/
package cmd

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

// -------------------------------- Cobra management -------------------------------

// generateCmd represents the generate command
var renameCmd = &cobra.Command{
	Use:   "rename",
	Short: "Rename the files in the cwd with bash",
	Long: `shaman rename
Reads the current tree, and puts into a bash script (stdout) that you can easily edit`,
	Aliases: []string{"ren"},
	Args:    cobra.MaximumNArgs(0),
	Run: func(cmd *cobra.Command, args []string) {
		ren(args)
	},
}

func init() {
	rootCmd.AddCommand(renameCmd)

	renameCmd.Flags().BoolVarP(&cli_flat, "flat", "", false, "Do not follow subdirectories)")
}

// ----------------------- Rename function below this line -----------------------

func ren(args []string) {
	num, _, _ := getSSFs(args)
	if num > 0 {
		abort(8, "Too many .ssf files specified)")
	}

	// Get the encoding path
	var startpath string = "."
	if cli_path != "" {
		startpath = cli_path // add validation here
	}

	// ------------------------------------------

	// call the tree walker to generate a file list (as a channel)
	fileQueue := make(chan triplex, 4096)
	go func() {
		defer close(fileQueue)
		walkTreeToChannel(startpath, fileQueue)
	}()

	// create move list *FIXME* needs pre-sizing
	for filerec := range fileQueue {
		fn := filerec.filename
		if cli_flat && strings.Index(fn, "/") > 0 {
			continue
		}
		q := "\"" + fn + "\""
		fmt.Printf("mv %-60s  %s\n", q, q)
	}

}
