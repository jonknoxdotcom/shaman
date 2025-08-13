/*
Copyright © 2025 Jon Knox <jon@k2x.io>
*/
package cmd

import (
	"github.com/spf13/cobra"

	"bufio"
	"fmt"
	"os"
	"strings"
)

// -------------------------------- Cobra management -------------------------------

// repathCmd represents the prefix command
var repathCmd = &cobra.Command{
	Use:   "shaman repath file.ssf [file2.ssf] -p path",
	Short: "Produces a modified version of the ssf file with the filenames modified by the depath/path strings",
	Long: `shaman repath file.ssf [file2.ssf] --unfix path --path path 
Produces a modified version of the ssf file with the filenames prefixed by the given string.
Performs the "unfix" first, and the "prefix" second.
Writes to stdout if no second file.  Writes errors for any lines that 'unfix' cannot process.
`,
	Aliases: []string{"repath"},
	Args:    cobra.MaximumNArgs(2),
	GroupID: "G2",
	Run: func(cmd *cobra.Command, args []string) {
		repath(args)
	},
}

func init() {
	rootCmd.AddCommand(repathCmd)

	repathCmd.Flags().StringVarP(&cli_unfix, "unfix", "", "", "Path to remove from filenames")
	repathCmd.Flags().StringVarP(&cli_prefix, "prefix", "", "", "Path to add to filenames")
}

// ----------------------- Repath function below this line -----------------------

// Example:
// shaman repath --unfix TEMP/ --prefix prod/
//
// changes
// xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx :TEMP/file.txt
// to:
// xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx :prod/file.txt

func repath(args []string) {
	num, files, found := getSSFs(args)
	if num > 2 {
		abort(8, "Too many .ssf files specified)")
	}
	if num == 0 {
		abort(8, "Need at least one .ssf file)")
	}
	fnr := files[0]
	if !found[0] {
		abort(8, "Cannot find "+fnr)
	}

	len_unfix := len(cli_unfix)
	len_prefix := len(cli_prefix)
	if len_prefix == 0 && len_unfix == 0 {
		abort(4, "No action to be performed!")
	}

	var r *os.File
	r, err := os.Open(fnr)
	if err != nil {
		abort(4, "Can't open "+fnr+" - stuck!")
	}
	defer r.Close()

	var s string
	var lineno int
	scanner := bufio.NewScanner(r)

	for scanner.Scan() {
		s = scanner.Text()
		// fmt.Println(s)
		lineno++
		if len(s) == 0 || s[0:1] == "#" {
			// drop comments or empty lines
			continue
		}

		// get rest of fields
		pos1 := strings.Index(s, " ")
		id := s[0:pos1]
		pos2 := strings.Index(s, " :")
		name := s[pos2+2:]
		len_name := len(name)

		// perform unfix
		if len_unfix != 0 {
			// fmt.Println(name)
			if len_unfix >= len_name {
				fmt.Printf("Line %d: impossible to unfix '%s'\n", lineno, name)
				continue
			}
			if name[0:len_unfix] != cli_unfix {
				fmt.Printf("Line %d: '%s' does not begin with unfix string\n", lineno, name)
				continue
			}
			name = name[len_unfix:]
			// fmt.Println(name)
		}

		// perform prefix
		if len_prefix != 0 {
			name = cli_prefix + name
			// fmt.Println(name)
		}

		fmt.Printf("%s :%s\n", id, name)
	}

	//w.Flush()
}
