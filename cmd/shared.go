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
	"sort"
	"strconv"
	"strings"
)

// ----------------------- Global variables (shared across 'cmd' package)

var cli_path string = ""    // Path to folder where scan will be performed [cobra]
var cli_format int = 0      // Format (0=default, 1=sha, 2=1+mod, 3=2+size, 4=3+name, 5=4+annotate, 6/7/8=unused, 9=sha256sum)
var cli_dupes bool = false  // Show duplicates as comments at end of run
var cli_grand bool = false  // Show grand total of files/bytes total at end
var cli_rehash bool = false // Perform deep integrity check by regenerating file hash and comparing (slow)
// var cli_summary bool = false   // Summarise changes from an update, without generating new file
var cli_overwrite bool = false // Overwrite file used in update with updated version (if there are changes)
var cli_verbose bool = false   // Provide verbose output (may have not effect)
var cli_del_b bool = false     // Delete from B anything that is in A
var cli_cwd bool = false       // Whether to recurse
var cli_flatten bool = false   // Whether to fold-down directories (using '--')
var cli_refile bool = false    // Whether to put files into directories (using '--')
var cli_incsha bool = false    // Include the SHA on delete listings

// var amWriting bool           // Whether writing
var dupes = map[string]int{} // duplicate scoreboard (collected during walk)

var cli_count int = 10
var cli_discard string = ""
var cli_equal bool = false
var cli_nodot bool = false

var cli_unfix string = ""
var cli_prefix string = ""

var cli_long bool = false   // used by compare
var cli_pixels bool = false // add pixel size to end of filename

var cli_check int = 0 // Port for health endpoint for use in 'detect'

var cli_asap bool = false       // speed is of the essence
var cli_noprecheck bool = false // suppress checking of environment
var cli_disclose bool = false   // add time-series disclosure

var cli_showform bool = false // determined format
var cli_strict bool = false   // strict failsafe rules (e.g. missing file raises error)

// ----------------------- General

// conditionalMessage used to reduce clutter for CLI application with a 'verbose' switch.
func conditionalMessage(cond bool, message string) {
	if cond {
		fmt.Println(message)
	}
}

// abort handled abnormal termination - centralised point for any break out of app.
// All internal fails are 10+.  All os.Exits across the app are centralised here
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

// storeLine converts a filename to something you can print on a single line.
// This is needed because it is possible to embed newlines (for instance) in a filename.
// Control chars can corrupt the file format. The SSF is designed to be resilient to this.
// THIS IS NOT WORKING
func storeLine(s string) string {
	var t string
	for _, rune := range s { // rune is actually an int32
		//if rune < 32 || (rune > 126 && rune <= 255) {
		if rune < 32 {
			t += fmt.Sprintf("\\x%02x", rune)
		} else if rune == '\\' {
			t += "\\\\"
			// } else if rune >= 256 && rune <= 65535 {
			// 	// NB missing character rune is 65533
			// 	t += fmt.Sprintf("\\u%04x", rune)
			// } else if rune >= 65536 {
			// 	t += fmt.Sprintf("\\x%06x", rune)
		} else {
			t += string(rune) // yes, you have to do this, but compiler optz'es
		}
		//		fmt.Printf("%d/%+q ", n, rune)
	}
	return t

	// s = strings.Replace(s, "\\", "\\\\", -1)
	// s = strings.Replace(s, "\r", "\\r", -1)
	// s = strings.Replace(s, "\n", "\\n", -1)
	// // need more control chars?
	// return s
}

// restoreLine is designed as the identity function to storeLine.
// Will take a 'stored filename' form (used in the SSFs) and return
// an exact string matching what the filesystem would call that file.
// Note: however, at the moment, it only reverses CR and LF.  *FIXME*
func restoreLine(s string) string {
	// s = strings.Replace(s, "\\x0a", string(10), -1)
	s = strings.Replace(s, "\\x0a", "\x0a", -1) // LF (NL)
	// s = strings.Replace(s, "\\x0d", string(13), -1)
	s = strings.Replace(s, "\\x0c", "\x0c", -1) // FF
	s = strings.Replace(s, "\\x0d", "\x0d", -1) // CR
	s = strings.Replace(s, "\\\\", "\\", -1)
	return s
}

// bashEscape used to amend quoted filenames to be resistant to shell metacharacters.
func bashEscape(fn string) string {
	fn = strings.Replace(fn, "\"", "\\\"", -1) // quote in filename would break our templates
	fn = strings.Replace(fn, "$", "\\$", -1)   // causes shell variable expansion
	fn = strings.Replace(fn, "~", "\\~", -1)   // causes user directory lookup
	fn = strings.Replace(fn, "*", "\\*", -1)   // yes, some people put stars in filenames
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
		x := len(s)
		return s[0:x-12] + "," + s[x-12:x-9] + "," + s[x-9:x-6] + "," + s[x-6:x-3] + "," + s[x-3:]
	case i < 1e18:
		x := len(s)
		return s[0:x-15] + "," + s[x-15:x-12] + "," + s[x-12:x-9] + "," + s[x-9:x-6] + "," + s[x-6:x-3] + "," + s[x-3:]
	default:
		return "X" + s
	}
}

// ----------------------- Functions that process files

// Return a list of verified files
func getAnySort(fileList []string) (int, []string, []bool) {
	sort.Strings(fileList)
	return getAny(fileList)
}

// Return a list of verified files
func getAny(fileList []string) (int, []string, []bool) {
	var flist []string
	var fexists []bool

	for _, fn := range fileList {
		flist = append(flist, fn)

		// do file read test (want it to fail)
		fd, err := os.Open(fn)
		fexists = append(fexists, err == nil)
		fd.Close()
	}

	return len(flist), flist, fexists
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

type binsha = [32]byte

// Compute SHA256 for a given filename, returning SHA256 in binary and string forms.
func getFileSha256(fn string) (binsha, string, error) {
	var binarySHASlice []byte

	f, err := os.Open(fn)
	if err != nil {
		// may happen (permissions lock)
		fmt.Fprintf(os.Stderr, "Found file cannot be opened: %s\n", fn)
		return binsha(binarySHASlice), "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		// shouldn't happen
		fmt.Fprintf(os.Stderr, "Found file cannot be processed: %s\n", fn)
		return binsha(binarySHASlice), "", err
	}
	binarySHASlice = h.Sum(nil)

	base64SHA := b64.StdEncoding.EncodeToString(binarySHASlice)
	if len(base64SHA) != 44 || base64SHA[43:] != "=" {
		// can't happen
		fmt.Fprintf(os.Stderr, "SHA result error for %s\n", fn)
		return binsha(binarySHASlice), "", err
	}
	base64SHA = base64SHA[0:43]

	return binsha(binarySHASlice), base64SHA, nil
}

func shaBase64ToShaBinary(sha_b64 string) binsha {
	sha, _ := b64.StdEncoding.DecodeString(sha_b64 + "=")
	// copy(shaCopy[0:31], sha[0:31])  -- can use cast
	return binsha(sha)
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
		// fmt.Println(s, shab64, modtime, size)
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
			if ok && val < modtime {
				// don't overwrite if stored modtime is earlier
				continue
			}
			hits[shab64] = modtime
		case 3:
			// record modtime and size
			val, ok := hits[shab64]
			if ok && val[0:8] < modtime {
				// don't overwrite if stored modtime is earlier
				continue
			}
			// fmt.Println(shab64, modtime, size)
			hits[shab64] = modtime + size
		}

		rows++
	}

	return len(hits), rows
}
