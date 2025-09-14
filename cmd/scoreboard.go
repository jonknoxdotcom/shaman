/*
Copyright © 2025 Jon Knox <jon@k2x.io>
*/
package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// ----------------------- Scoreboards

// ssfScoreboardRead(fn string, m map[string]bool, flag bool) (int, int)
// ssfScoreboardMark(fn string, m map[string]bool, flag bool) (int, int)
// ssfScoreboardRemove(m map[string]bool, target bool) int
// ssfSelectNameByScoreboard(fn string, m map[string]bool, list *[]string) int
// ssfScoreboardDupRead(fn string, m map[string]bool) (int, int)
// sshScoreboardReadMapMap(multiple map[string]bool, fn string, first map[string]string, report map[string]string) (int, int)
// ssfCollectRead(fnr string, hits map[string]string, format int) (int, int)
// splitSSFLine(s string) (id string, shab64 string, modtime string, length string, name string)

// ssfScoreboardRead reads the given ssf file, and create a key=sha, value=flag in map m / return length.
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
