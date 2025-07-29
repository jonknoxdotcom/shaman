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
	GroupID: "G3",

	Args: cobra.MaximumNArgs(0),
	Run: func(cmd *cobra.Command, args []string) {
		ren(args)
	},
}

func init() {
	rootCmd.AddCommand(renameCmd)

	renameCmd.Flags().BoolVarP(&cli_cwd, "cwd", "", false, "Current working directory only (no subdirectories)")
	renameCmd.Flags().BoolVarP(&cli_flatten, "flatten", "", false, "Flatten all files to single directory")
	renameCmd.Flags().BoolVarP(&cli_refile, "refile", "", false, "Re-file single files into folders")
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
	var folder string
	var lastfolder string
	for filerec := range fileQueue {
		fn := filerec.filename
		if cli_cwd && strings.Index(fn, "/") > 0 {
			continue
		}
		fmt.Println(fn)
		source := "\"" + strings.Replace(fn, "\"", "\\\"", -1) + "\""
		dest := source
		if cli_flatten {
			// completely flatten
			dest = strings.Replace(dest, "/", "--", -1)
		}
		if cli_refile {
			// only expand 1-deep tree
			dest = strings.Replace(dest, "--", "/", 1)
			pos := strings.Index(dest, "/")
			if pos != -1 {
				folder = dest[1:pos]
			}
		}
		if folder != lastfolder {
			fmt.Printf("mkdir \"%s\"\n", folder)
			lastfolder = folder
		}
		fmt.Printf("mv %-60s  %s\n", source, dest)
	}

}
