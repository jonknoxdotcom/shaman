/*
Copyright © 2025 Jon Knox <jon@k2x.io>
*/
package cmd

import (
	"bufio"
	"crypto/sha256"
	"encoding/base64"
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
var cli_format int = 1      // Format (0=default, 1=sha, 2=1+mod, 3=2+size, 4=3+name, 5=4+annotate, 6/7/8=unused, 9=sha256sum)
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

var cli_ending string = "" // only consider files with this ending

var cli_noempty = false // do not allow hash for empty file to appear
var cli_chaff = 0       // chaff volume - approx number of records to add (default: 0 = off)
var cli_plusbin = false // add a .bin version of file

// ----------------------- Shared functions

// conditionalMessage(cond bool, message string)
// abort(rc int, reason string)
// storeLine(s string) string
// restoreLine(s string) string
// bashEscape(fn string) string
// intAsStringWithCommas(i int64) string
// getAnySort(fileList []string) (int, []string, []bool)
// getAny(fileList []string) (int, []string, []bool)
// getSSFs(flist []string) (int, []string, []bool)
// getFileSha256(fn string) (binsha, string, error)
// shaBase64ToShaBinary(sha_b64 string) binsha
// reportGrandTotals(w *bufio.Writer, tf int64, tb int64)
// reportDupes(w *bufio.Writer)
// ssfRecCount(fn string) int64
// isBase64(s string) bool
// isHexadecimal(s string) bool

// ----------------------- Messages

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

func conditionalAbort(bad bool, rc int, reason string) {
	if bad {
		abort(rc, reason)
	}
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
	s = strings.ReplaceAll(s, "\\x0a", "\x0a") // LF (NL)
	s = strings.ReplaceAll(s, "\\x0c", "\x0c") // FF
	s = strings.ReplaceAll(s, "\\x0d", "\x0d") // CR
	s = strings.ReplaceAll(s, "\\\\", "\\")
	return s
}

// bashEscape used to amend quoted filenames to be resistant to shell metacharacters.
func bashEscape(fn string) string {
	fn = strings.ReplaceAll(fn, "\"", "\\\"") // quote in filename would break our templates
	fn = strings.ReplaceAll(fn, "$", "\\$")   // causes shell variable expansion
	fn = strings.ReplaceAll(fn, "~", "\\~")   // causes user directory lookup
	fn = strings.ReplaceAll(fn, "*", "\\*")   // yes, some people put stars in filenames
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

// ---- Checkers

func isBase64(s string) bool {
	_, err := base64.StdEncoding.DecodeString(s + "=")
	return err == nil
}

// isHexadecimal returns validation of likely hexadecimal number that can be odd or even nybbles long.
// *FIXME* possible refactor the loop logic
func isHexadecimal(s string) bool {
	// fmt.Println("hex:", s)
	for i := 0; i < len(s); i++ {
		ch := s[i : i+1]
		if !strings.Contains("0123456789abcdef", ch) {
			return false
		}
	}
	return true
}
