/*
Copyright © 2025 Jon Knox <jon@k2x.io>
*/
package cmd

import (
	"bufio"
	"crypto/sha256"
	b64 "encoding/base64"
	"fmt"
	"io"
	"maps"
	"os"
	"path"
	"slices"
	"strconv"
)

// ----------------------- Global variables (shared across 'cmd' package)

var cli_path string = ""       // Path to folder where scan will be performed [cobra]
var cli_anon bool = false      // Anonymise the output (discard file, modified time and size)
var cli_dupes bool = false     // Show duplicates as comments at end of run
var cli_grand bool = false     // Show grand total of files/bytes total at end
var cli_rehash bool = false    // Perform deep integrity check by regenerating file hash and comparing (slow)
var cli_summary bool = false   // Summarise changes from an update, without generating new file
var cli_overwrite bool = false // Overwrite file used in update with updated version (if there are changes)
var cli_verbose bool = false   // Provide verbose output (may have not effect)

var dupes = map[string]int{} // duplicate scoreboard (collected during walk)

// ----------------------- General

// Abnormal termination - break out of app, all internal fails are 10+
// All os.Exits across the app are centralised here
func abort(rc int, reason string) {
	if rc < 10 {
		if reason != "" {
			fmt.Println(reason)
		}
	} else {
		fmt.Println("Internal error: " + reason)
		fmt.Println("(Please report to help us improve this tool)")
	}
	os.Exit(rc)
}

// Return a list of verified SSFs. **FIXME**
func getSSFs(flist []string) (int, []string, []bool) {
	var ssflist []string
	var ssfexists []bool

	for _, fn := range flist {
		// named file - check it's a valid name
		if len(fn) < 5 || fn[len(fn)-4:] != ".ssf" {
			abort(6, "file '"+fn+"' does not end with '.ssf'")
		}
		ssflist = append(ssflist, fn)

		// do file read test (want it to fail)
		fd, err := os.Open(fn)
		ssfexists = append(ssfexists, err == nil)
		fd.Close()
	}

	///fmt.Println(len(ssflist), ssflist, ssfexists)
	return len(ssflist), ssflist, ssfexists
}

// ----------------------- Hashing

// Compute SHA256 for a given filename, returning byte array x 32 and truncated b64 hash
func getFileSha256(fn string) ([]byte, string) {
	f, err := os.Open(fn)
	if err != nil {
		// shouldn't happen
		abort(13, "Found file cannot be opened: "+fn)
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		// shouldn't happen
		abort(14, "Found file cannot be processed: "+fn)
	}

	sha_bin := h.Sum(nil)
	sha_b64 := b64.StdEncoding.EncodeToString(sha_bin)
	if len(sha_b64) != 44 || sha_b64[43:] != "=" {
		// can't happen
		abort(3, "sha result error for "+fn)
	}
	sha_b64 = sha_b64[0:43]

	return sha_bin, sha_b64
}

// ----------------------- Reporting

// Reproducible comment on total number of files/bytes
func reportGrandTotals(w *bufio.Writer, tf int64, tb int64) {
	if cli_grand {
		out := fmt.Sprintf("# %d files, %d bytes", tf, tb)
		fmt.Fprintln(w, out)
	}
}

// Reproducible comment on duplicate hashes
func reportDupes(w *bufio.Writer) {
	if cli_dupes {
		var multi = map[string]int{} // duplicate>2 hits table
		for id, times := range dupes {
			if times > 1 {
				multi[id] = times
			}
		}
		if len(multi) == 0 {
			fmt.Fprintln(w, "# There were no duplicates")
		} else {
			fmt.Fprintln(w, "# ----------------- Duplicates -----------------")
			for _, id := range slices.Sorted(maps.Keys(multi)) {
				fmt.Fprintln(w, "# "+id+" x"+strconv.Itoa(multi[id]))
			}
		}
	}
}

// ----------------------- Directory traversal (producer)

type triplex struct {
	filename string
	modified int64
	size     int64
}

func walkTreeToChannel(startpath string, c chan triplex) {
	entries, err := os.ReadDir(startpath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Skipping directory: %s\n", startpath)
		return
	}

	// step through contents of this dir
	for _, entry := range entries {
		if !entry.IsDir() {
			if !entry.Type().IsRegular() {
				// we ignore symlinks
				continue
			}

			name := path.Join(startpath, entry.Name())
			info, err := entry.Info()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Skipping entry: %s\n", name)
				continue
			}

			c <- triplex{name, info.ModTime().Unix(), info.Size()}
		} else {
			// it's a directory - dig down
			walkTreeToChannel(path.Join(startpath, entry.Name()), c)
		}
	}
}
