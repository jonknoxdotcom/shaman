/*
Copyright © 2025 Jon Knox <jon@k2x.io>
*/
package cmd

import (
	"fmt"

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
var cli_path string = ""        // Path to folder where scan will be performed [cobra]
var dupes = map[string]uint32{} // duplicates (collected during walk)

// generateCmd represents the generate command
var generateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generate a sha-manager signature (.ssf) file",
	Long: `Generate a sha-manager (.ssf) file from specified directory (or current directory if none specified), 
writing the output to a named file (or stdout if none given)`,
	Aliases: []string{"gen"},
	Run: func(cmd *cobra.Command, args []string) {
		gen(cli_path)
	},
}

func init() {
	rootCmd.AddCommand(generateCmd)

	generateCmd.Flags().StringVarP(&cli_path, "path", "p", "", "Path to directory to scan (default is current directory)")

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

func WalkTree(startpath string) (int64, error) {
	// uses the "new" (1.16) os.ReadPath functionality
	entries, err := os.ReadDir(startpath)
	if err != nil {
		abort(1, "Unrecoverable failure to read directory")
	}
	var total int64
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
			unixtime := info.ModTime().Unix()
			// mode := info.Mode() // looks like '-rwxr-xr-x', alsoi synonymous to entry.Type().Perm()

			sha, _ := GetSha256OfFile(name)
			shab64 := b64.StdEncoding.EncodeToString(sha)
			if len(shab64) != 44 {
				// can't happen
				abort(3, "Internal error #3: "+name)
			}
			if shab64[43:] != "=" {
				// can't happen
				abort(4, "Internal error #4: "+name)
			} else {
				shab64 = shab64[0:43]
			}
			dupes[shab64] = dupes[shab64] + 1

			fmt.Printf("%s%x%04x :%s", shab64, unixtime, size, name)
			fmt.Println()
		}
		if entry.IsDir() {
			size, err := WalkTree(path.Join(startpath, entry.Name()))
			if err != nil {
				return 0, err
			}
			total += size
		} else {
			info, err := entry.Info()
			if err != nil {
				return 0, err
			}
			total += info.Size()
		}
	}
	return total, nil
}

func gen(startpath string) {

	// Run the generator
	if startpath == "" {
		startpath = "."
	}
	_, _ = WalkTree(startpath)

	// This directory reader uses the new os.ReadDir (req 1.16)
	// https://benhoyt.com/writings/go-readdir/

	for id, times := range dupes {
		if times > 1 {
			fmt.Println("# " + id)
		}
	}

}
