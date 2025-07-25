/*
Copyright © 2025 Jon Knox <jon@k2x.io>
*/
package cmd

import (
	"bufio"
	"crypto/sha256"
	"fmt"
	"io"
	"maps"
	"os"
	"path"
	"slices"
	"strconv"
)

// Local variables shared across 'cmd' package
var cli_path string = ""     // Path to folder where scan will be performed [cobra]
var cli_anon bool = false    // Anonymise the output (discard file, modified time and size)
var cli_dupes bool = false   // Show duplicates as comments at end of run
var cli_totals bool = false  // Show files/bytes total at end of run
var dupes = map[string]int{} // duplicate scoreboard (collected during walk)

// Compute SHA256 for a given filename, returning byte array x 32
func getSha256OfFile(fn string) ([]byte, error) {
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

// Return a list of verified SSFs
func getSSFs(flist []string) (int, []string, []bool) {
	var ssflist []string
	var ssfexists []bool

	if len(flist) == 1 {
		// named file - check it's a valid name
		fn := flist[0]
		if len(fn) < 5 || fn[len(fn)-4:] != ".ssf" {
			abort(6, "file '"+fn+"' does not end with '.ssf'")
		}
		ssflist = append(ssflist, fn)

		// do file read test (want it to fail)
		fd, err := os.Open(fn)
		ssfexists = append(ssfexists, err == nil)
		fd.Close()
	}

	return len(ssflist), ssflist, ssfexists
}

// Reproducible comment on total number of files/bytes
func reportTotals(w *bufio.Writer, tf int64, tb int64) {
	if cli_totals {
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

// Directory walking producer

type triplex struct {
	filename string
	modified int64
	size     int64
}

func walkTreeToChannel(startpath string, c chan triplex) {
	entries, err := os.ReadDir(startpath)
	if err != nil {
		abort(5, "Unable to read directory (typo?)")
	}

	// step through dirs
	for _, entry := range entries {
		if !entry.IsDir() {
			if !entry.Type().IsRegular() {
				// we ignore symlinks
				continue
			}

			name := path.Join(startpath, entry.Name())
			info, err := entry.Info()
			if err != nil {
				abort(10, "entry lookup failure for "+name)
			}

			c <- triplex{name, info.ModTime().Unix(), info.Size()}
		} else {
			// it's a directory - dig down
			walkTreeToChannel(path.Join(startpath, entry.Name()), c)
		}
	}
}
