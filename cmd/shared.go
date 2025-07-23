/*
Copyright © 2025 Jon Knox <jon@k2x.io>
*/
package cmd

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
)

// Local variables shared across 'cmd' package
var cli_path string = ""     // Path to folder where scan will be performed [cobra]
var cli_anon bool = false    // Anonymise the output (discard file, modified time and size)
var cli_dupes bool = false   // Show duplicates as comments at end of run
var cli_totals bool = false  // Show files/bytes total at end of run
var dupes = map[string]int{} // duplicates (collected during walk)

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

// Failure - break out of app
func abort(rc int, reason string) {
	fmt.Println(reason)
	os.Exit(rc)
}

// Return a list of verified SSFs
func getSSFs(flist []string) (int, []string, []bool) {
	var ssflist []string
	var ssfexists []bool

	if len(flist) == 1 {
		// named file - check it's a valid name
		fn := flist[0]
		if len(fn) < 5 || fn[len(fn)-4:] != ".ssf" {
			abort(6, "File '"+fn+"' does not end with '.ssf'")
		}
		ssflist = append(ssflist, fn)

		// do file read test (want it to fail)
		fd, err := os.Open(fn)
		ssfexists = append(ssfexists, err == nil)
		fd.Close()
	}

	return len(ssflist), ssflist, ssfexists
}
