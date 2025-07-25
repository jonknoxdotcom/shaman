/*
Copyright © 2025 Jon Knox <jon@k2x.io>
*/
package cmd

import (
	"github.com/spf13/cobra"

	"fmt"
)

// -------------------------------- Cobra management -------------------------------

// estimateCmd represents the generate command
var estimateCmd = &cobra.Command{
	Use:   "estimate",
	Short: "Estimate quickly the size/count for a file tree",
	Long: `shaman estimate
Used to count the number of files in the file tree, to allow you to perform informed actions!`,
	Aliases: []string{"est"},
	Args:    cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		est(args)
	},
}

func init() {
	rootCmd.AddCommand(estimateCmd)

	estimateCmd.Flags().StringVarP(&cli_path, "path", "p", "", "Path to directory to scan (default is current directory)")
}

// ----------------------- Estimate function below this line -----------------------

// Rate: 70k files per sec for Desktop on MBP A2141

func est(args []string) {
	num, _, _ := getSSFs(args)
	if num > 0 {
		abort(8, "Can't estimate on a file at the moment)")
	}

	// Get the encoding path
	var startpath string = "."
	if cli_path != "" {
		startpath = cli_path // add validation here
	}

	// Call the tree walker to generate a file list (as a channel)
	fileQueue := make(chan triplex, 4096)
	go func() {
		defer close(fileQueue)
		walkTreeToChannel(startpath, fileQueue)
	}()

	// process file list to provide stats
	var total_files int64
	var total_bytes int64
	var longest int
	var mem_long string
	var largest int64
	var mem_large string
	for filerec := range fileQueue {
		if longest < len(filerec.filename) {
			longest = len(filerec.filename)
			mem_long = filerec.filename
		}
		if largest < filerec.size {
			largest = filerec.size
			mem_large = filerec.filename
		}
		total_bytes += filerec.size
		total_files++
	}

	// Totals
	fmt.Printf("Total files:  %d", total_files)
	fmt.Println()
	fmt.Printf("Total bytes:  %d", total_bytes)
	fmt.Println()
	fmt.Printf("Largest file: %d %s", largest, mem_large)
	fmt.Println()
	fmt.Printf("Longest name: %d %s", longest, mem_long)
	fmt.Println()
}
