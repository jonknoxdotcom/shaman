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
	"slices"
	"strconv"
	"strings"
)

// ----------------------- Global variables (shared across 'cmd' package)

var cli_path string = ""       // Path to folder where scan will be performed [cobra]
var cli_format int = 5         // Format /anonymisation (0=sha256, 1=sha, 2=sha+mod, 3=sha+mod+size, 4=+name, 5=allow all data)
var cli_dupes bool = false     // Show duplicates as comments at end of run
var cli_grand bool = false     // Show grand total of files/bytes total at end
var cli_rehash bool = false    // Perform deep integrity check by regenerating file hash and comparing (slow)
var cli_summary bool = false   // Summarise changes from an update, without generating new file
var cli_overwrite bool = false // Overwrite file used in update with updated version (if there are changes)
var cli_verbose bool = false   // Provide verbose output (may have not effect)
var cli_del_b bool = false     // Delete from B anything that is in A
var cli_cwd bool = false       // Whether to recurse
var cli_flatten bool = false   // Whether to fold-down directories (using '--')
var cli_refile bool = false    // Whether to put files into directories (using '--')
var cli_incsha bool = false    // Include the SHA on delete listings

var amWriting bool           // Whether writing
var dupes = map[string]int{} // duplicate scoreboard (collected during walk)

var cli_count int = 10
var cli_discard string = ""
var cli_ellipsis bool = false
var cli_nodot bool = false

var cli_unfix string = ""
var cli_prefix string = ""

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

func bashEscape(fn string) string {
	fn = strings.Replace(fn, "\"", "\\\"", -1)
	fn = strings.Replace(fn, "$", "\\$", -1)
	fn = strings.Replace(fn, "~", "\\~", -1)
	return fn
}

func intAsStringWithCommas(i int64) string {
	s := fmt.Sprintf("%d", i)
	switch true {
	case i < 1e3:
		return s
	case i < 1e6:
		x := len(s)
		return s[0:x-3] + "," + s[x-3:]
	case i < 1e9:
		x := len(s)
		return s[0:x-6] + "," + s[x-6:x-3] + "," + s[x-3:]
	case i < 1e12:
		x := len(s)
		return s[0:x-9] + "," + s[x-9:x-6] + "," + s[x-6:x-3] + "," + s[x-3:]
	case i < 1e15:
		return "X" + s
	}
	//15,103,984,154
	return s
}

// ----------------------- Functions that process files

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
	//fmt.Print("*")
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

func shaBase64ToShaBinary(sha_b64 string) []byte {
	shabin, _ := b64.StdEncoding.DecodeString(sha_b64 + "=")
	return shabin
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

// ----------------------- File processing

// return the number of lines with a sha in a file (NOT the number of unique shas)
func ssfRecCount(fn string) int64 {
	var r *os.File
	r, err := os.Open(fn)
	if err != nil {
		abort(4, "Can't open "+fn+" - stuck!")
	}
	defer r.Close()

	var count int64
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		s := scanner.Text()
		if len(s) == 0 || s[0:1] == "#" {
			// drop comments or empty lines
			continue
		}
		count++
	}
	return count
}

// ----------------------- Scoreboards

// read the given ssf file, and create a key=sha, value=flag in map m / return length
func ssfScoreboardRead(fn string, m map[string]bool, flag bool) (int, int) {
	var r *os.File
	r, err := os.Open(fn)
	if err != nil {
		abort(4, "Can't open "+fn+" - stuck!")
	}
	defer r.Close()

	var count int
	var s string
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		s = scanner.Text()
		if len(s) == 0 || s[0:1] == "#" {
			// drop comments or empty lines
			continue
		} else {
			// set flag with base64 part
			m[s[0:43]] = flag
			count++
		}
	}

	return len(m), count
}

// read a file and set map entry to flag only if the sha exists in the map
func ssfScoreboardMark(fn string, m map[string]bool, flag bool) (int, int) {
	var r *os.File
	r, err := os.Open(fn)
	if err != nil {
		abort(4, "Can't open "+fn+" - stuck!")
	}
	defer r.Close()

	var count int
	var hits int
	var s string
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		s = scanner.Text()
		if len(s) == 0 || s[0:1] == "#" {
			// drop comments or empty lines
			continue
		} else {
			// set flag with base64 part
			k := s[0:43]
			_, ok := m[k]
			if ok {
				m[k] = flag
				///fmt.Println(k)
				hits++
			}
			count++
		}
	}

	return count, hits
}

// remove all of the map entries that are of value target
func ssfScoreboardRemove(m map[string]bool, target bool) int {
	// fine to delete map during loop https://go.dev/doc/effective_go#for
	// basic but useful https://leapcell.io/blog/how-to-delete-from-a-map-in-golang
	for k, v := range m {
		if v == target {
			delete(m, k)
		}
	}

	return len(m)
}

// read the given ssf file, and create a key=sha, value=flag in map m / return length
func ssfSelectNameByScoreboard(fn string, m map[string]bool, list *[]string) int {
	var r *os.File
	r, err := os.Open(fn)
	if err != nil {
		abort(4, "Can't open "+fn+" - stuck!")
	}
	defer r.Close()

	var s string
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		s = scanner.Text()
		if len(s) == 0 || s[0:1] == "#" {
			// drop comments or empty lines
			continue
		}

		_, ok := m[s[0:43]]
		if ok {
			pos := strings.Index(s, " :")
			if pos == -1 {
				fmt.Println("Junk line: " + s)
			} else {
				t := s[pos+2:]
				*list = append(*list, t)
			}
		}
	}

	return len(*list)
}

// ssfScoreboardDupRead - entry per SHA, bool false if one, true if multi
func ssfScoreboardDupRead(fn string, m map[string]bool) (int, int) {
	var r *os.File
	r, err := os.Open(fn)
	if err != nil {
		abort(4, "Can't open "+fn+" - stuck!")
	}
	defer r.Close()

	var multi int
	var s string
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		s = scanner.Text()
		if len(s) == 0 || s[0:1] == "#" {
			// drop comments or empty lines
			continue
		} else {
			// get key
			k := s[0:43]

			v, ok := m[k]
			if ok {
				// existing
				if !v {
					m[k] = true
					multi++
				}
			} else {
				// new
				m[k] = false
			}
		}
	}

	return len(m), multi
}

// Split a line from an SSF into constituent fields (no hex to dec conversion) / empty str on error
func splitSSFLine(s string) (id string, shab64 string, modtime string, length string, name string) {
	pos := strings.IndexByte(s, 32)
	if pos == -1 {
		return "", "", "", "", ""
	}
	id = s[0:pos]
	shab64 = s[0:43]
	modtime = s[43:51]
	length = s[51:pos]
	name = s[pos+2:]
	return id, shab64, modtime, length, name
}

// Take scoreboard and filename, and return 'first use' map and 'reports' strings map
// We generate two maps:
//
//	first[]  : key=filename, val=sha  (the first filename to use this sha)
//	report[] : key=sha, value=2-5 lines of \n-seperated escaped filenames
//
// 1. collect the first names and the report data at same time
// 2. sort the first table to get report order
// 3. step through first[], get the sha, and get the contents of the report[sha]
// e.g.
// reports = 1
// first["Lead Title"] = "abcd1234"
// report["abcd1234"] = "Subordinate One\nSubordinate Two"
func sshScoreboardReadMapMap(multiple map[string]bool, fn string, first map[string]string, report map[string]string) (int, int) {

	// first["Lead Title"] = "abcd1234"
	// report["abcd1234"] = "Subordinate One\nSubordinate Two"

	// id, _, _, _, _ := splitSSFLine("7xSM0/XwrVYCmUQVNm8XdH7MLURqiwoUs5cRNW0bMQ4685c319d1a6039 :2025-06-19 ransomeware bust thailand.png")
	// fmt.Println(id)
	// id = fn
	// multiple["ss"] = false
	// return 1

	var r *os.File
	r, err := os.Open(fn)
	if err != nil {
		abort(4, "Can't open "+fn+" - stuck!")
	}
	defer r.Close()

	var s string
	var tm int
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		s = scanner.Text()
		if len(s) == 0 || s[0:1] == "#" {
			// drop comments or empty lines
			continue
		} else {
			// do something
			_, shab64, _, _, name := splitSSFLine(s)
			if shab64 == "" {
				fmt.Println("Ignoring corrupt line: " + s)
				continue
			}
			if !multiple[shab64] {
				continue
			}

			tm++
			name = bashEscape(name)
			//fmt.Println("multi " + shab64 + " : " + name)

			v, ok := report[shab64]
			//fmt.Println(ok, v)
			if !ok {
				// must be lead title
				//fmt.Println("LEAD")
				first[name] = shab64
				report[shab64] = ""
			} else {
				//fmt.Println("SUBORDINATE")
				// already have lead
				if v == "" {
					// first subordinate
					report[shab64] = name
				} else {
					// later subordinates
					report[shab64] += "\n" + name
				}
			}

		}
	}
	return len(first), tm
}

// Consolidation functions

func ssfCollectRead(fnr string, hits map[string]string, format int) (int, int) {
	var r *os.File
	r, err := os.Open(fnr)
	if err != nil {
		abort(4, "Can't open "+fnr+" - stuck!")
	}
	defer r.Close()

	var rows int
	var s string
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		s = scanner.Text()
		if len(s) == 0 || s[0:1] == "#" {
			// drop comments or empty lines
			continue
		}

		// get fields
		_, shab64, modtime, size, _ := splitSSFLine(s)
		if shab64 == "" {
			fmt.Println("Ignoring corrupt line: " + s)
			continue
		}

		switch format {
		case 1:
			// just the SHA
			hits[shab64] = ""
		case 2:
			// record modtime
			val, ok := hits[shab64]
			if ok && val > modtime {
				// don't overwrite if stored modtime is earlier
				continue
			}
			hits[shab64] = modtime
		case 3:
			// record modtime and size
			val, ok := hits[shab64]
			if ok && val[0:8] > modtime {
				// don't overwrite if stored modtime is earlier
				continue
			}
			hits[shab64] = modtime + ":" + size
		}

		rows++
	}

	return len(hits), rows

}
