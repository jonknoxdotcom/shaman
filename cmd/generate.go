/*
Copyright © 2025 Jon Knox <jon@k2x.io>
*/
package cmd

import (
	"fmt"
	"strconv"

	"github.com/spf13/cobra"

	//"bufio"
	//"encoding/json"
	"os"
	"path"

	"crypto/sha256"
	"io"

	b64 "encoding/base64"
)

// Local variables
var cli_path string = ""     // Path to folder where scan will be performed [cobra]
var cli_anon bool = false    // Anonymise the output (discard file, modified time and size)
var cli_dupes bool = false   // Show duplicates as comments at end of run
var cli_totals bool = false  // Show files/bytes total at end of run
var dupes = map[string]int{} // duplicates (collected during walk)

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

// Compute SHA256 for a given filename, returning byte array x 32
func GetSha256OfFile(fn string) ([]byte, error) {
	f, err := os.Open(fn)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return nil, err
	}

	return h.Sum(nil), nil
}

func abort(rc int, reason string) {
	fmt.Println(reason)
	os.Exit(rc)
}

func WalkTree(startpath string) (int64, int64, error) {
	// uses the "new" (1.16) os.ReadPath functionality
	entries, err := os.ReadDir(startpath)
	if err != nil {
		abort(1, "Unrecoverable failure to read directory")
	}
	var total_files int64
	var total_bytes int64
	for _, entry := range entries {
		if !entry.IsDir() {
			// we ignore symlinks
			if !entry.Type().IsRegular() {
				continue
			}
			// emit file data
			name := path.Join(startpath, entry.Name())
			info, err := entry.Info()
			if err != nil {
				abort(2, "Internal error #2")
			}
			size := info.Size()

			sha_bin, _ := GetSha256OfFile(name)
			sha_b64 := b64.StdEncoding.EncodeToString(sha_bin)
			if len(sha_b64) != 44 || sha_b64[43:] != "=" {
				// can't happen
				abort(3, "Internal error #3: "+name)
			}
			sha_b64 = sha_b64[0:43]
			dupes[sha_b64] = dupes[sha_b64] + 1

			if cli_anon {
				fmt.Println(sha_b64)
			} else {
				unixtime := info.ModTime().Unix()
				// mode := info.Mode() // looks like '-rwxr-xr-x', alsoi synonymous to entry.Type().Perm()
				fmt.Printf("%s%x%04x :%s", sha_b64, unixtime, size, name)
				fmt.Println()
			}
			total_bytes += size
			total_files++
		} else {
			// it's a directory - traverse
			files, size, err := WalkTree(path.Join(startpath, entry.Name()))
			if err != nil {
				return 0, 0, err
			}
			total_files += files
			total_bytes += size
		}
	}
	return total_files, total_bytes, nil
}

func gen(args []string) {

	// Get the encoding path
	var startpath string = "."
	if cli_path != "" {
		startpath = cli_path // add validation here
	}

	// Check whether file specified and if so that it does not yet exist and that it ends ".ssf"
	if len(args) == 1 {

	}

	// Call the tree walker
	tf, tb, err := WalkTree(startpath)
	if err != nil {
		abort(5, "Internal error #5: ")
	}

	// Optional totals statement
	if cli_totals {
		fmt.Printf("# %d files, %d bytes", tf, tb)
		fmt.Println()
	}

	// This directory reader uses the new os.ReadDir (req 1.16)
	// https://benhoyt.com/writings/go-readdir/

	// Optional duplicates statement
	done_header := false
	if cli_dupes {
		for id, times := range dupes {
			if times > 1 {
				if !done_header {
					fmt.Println("# ----------------- Duplicates -----------------")
					done_header = true
				}
				fmt.Println("# " + id + " x" + strconv.Itoa(times))
			}
		}
		if !done_header {
			fmt.Println("# There were no duplicates")
		}
	}

}
