/*
Copyright © 2025 Jon Knox <jon@k2x.io>
*/
package cmd

import (
	"fmt"
	"strconv"
	"time"
)

// ----------------------- "Topper" functions (used by latest.go and biggest.go)

// globs
var topKeys []string  // that which we sort on (number or modtime)
var topIdens []string // identifier block
var topNames []string // reporting name
var topDepth int      // size of the table (N) to be produced (taking into account duplicates)
var topLinesUsed int  // actual number of lines used in the table

// set up topper (can be size or date)
func topInit(n int, defaultKey string) {
	// slog.Debug("topInit", "defaultKey", defaultKey)

	topDepth = n
	topKeys = make([]string, n)  // that which we sort on
	topIdens = make([]string, n) // identifier block
	topNames = make([]string, n) // reporting name

	for x := 0; x < n; x++ {
		topKeys[x] = defaultKey
		topNames[x] = "(no entry)"
		topIdens[x] = ""
	}
}

func topAdd(key string, id string, name string) string {
	// fmt.Println("\ntA ", key, id, name)
	//slog.Debug("topAdd", "id", id, "name", name, "topLinesUsed", topLinesUsed)
	// topReportBySizeDebug("\n*****INTERMEDIATE %d *****\n")

	// first half - figure out where to insert record (or exit if off end of table)
	// second half - perform insertion (shuffle down)

	var pos int
	switch {
	case topLinesUsed == 0:
		// we are in virgin table
		// fmt.Println("VIRGIN")
		pos = 0

	case key <= topKeys[topLinesUsed-1]:
		// fmt.Println("APPEND")
		// record will go at the end (or will drop if table fully inflated)
		if topDepth == topLinesUsed {
			// rapid reject when element is off the end of full table
			// fmt.Println("early exit - key is after eot and table is inflated")
			return topKeys[topDepth-1]
		} else {
			pos = topLinesUsed
			// fmt.Println("appending at ", pos)
		}

	default:
		// fmt.Println("SEARCH (NB the last line currently will def be lost)")

		// find where in the table the entry should go
		pos = topLinesUsed - 1 // point to last populated row
		// fmt.Println("inserting", key, "above or at pos=", pos, "(topDepth=", topDepth, ", topLinesUsed=", topLinesUsed, ")")
		for {
			// fmt.Println("loop -  pos=", pos)

			// shift content down
			if pos < topDepth-1 {
				// fmt.Println("/ copying ", pos, "to", pos+1)
				topKeys[pos+1] = topKeys[pos]
				topNames[pos+1] = topNames[pos]
				topIdens[pos+1] = topIdens[pos]
			}

			if pos == 0 {
				// fmt.Print("\nmust be at head")
				break
			}

			if key <= topKeys[pos-1] {
				// fmt.Print("\n", "BREAK: ", topKeys, "<", topKeys[pos], " pos=", pos, "\n")
				break
			}

			pos--
		}
		// fmt.Println("out of loop, pos=", pos)
	}

	// write in the record at row 'pos'
	// fmt.Printf("tA: record write: key=%s at pos=%d\n", key, pos)
	topKeys[pos] = key
	topNames[pos] = name
	topIdens[pos] = id

	if topLinesUsed < topDepth {
		topLinesUsed++
	}

	if topLinesUsed < topDepth {
		// thresh allow all (table not inflated)
		return ""
	} else {
		// thresh has hard value
		return topKeys[topDepth-1]
	}
}

func topReportBySize(title string) {
	nrows := min(topLinesUsed, topDepth)
	fmt.Printf(title, nrows)

	fmt.Println("POS   HEX SIZE     -----SIZE-----   FILENAME")
	var decNum int64 = 0
	var lastNum int64 = 0
	var lastSHA string = ""
	var place int = 0
	for x := 0; x < nrows; x++ {
		decNum, _ = strconv.ParseInt(topKeys[x], 16, 0)

		// fmt.Println("'" + lastSHA + "'")
		// fmt.Println("'" + topIdens[x] + "'")
		// fmt.Println(lastSHA == topIdens[x])
		if lastSHA == topIdens[x] && lastSHA[0:43] == topIdens[x][0:43] {
			// print line indicating dupe - why not working??
			fmt.Printf("%2d= %11s%18s   %s\n", place, topKeys[x], "same^", topNames[x])

		} else if !cli_equal || decNum != lastNum {
			// print full line every time
			fmt.Printf("%2d: %11s%18s   %s\n", x+1, topKeys[x], intAsStringWithCommas(decNum), topNames[x])
			place = x + 1

		} else {
			// use equal to denote repeated sizes/hashes
			fmt.Printf("%2d= %11s%18s   %s\n", place, "          ", "         ", topNames[x])
		}

		lastNum = decNum
		lastSHA = topIdens[x]
	}
}

// func topReportBySizeDebug(title string) {
// 	fmt.Println("tRSD")
// 	fmt.Println("topLinesUsed=", topLinesUsed)
// 	nrows := min(topLinesUsed, topDepth)
// 	fmt.Printf(title, nrows)
// 	fmt.Println("POS   HEX SIZE   -----SIZE-----  FILENAME")
// 	var decNum int64 = 0
// 	for x := 0; x < topDepth; x++ {
// 		decNum, _ = strconv.ParseInt(topKeys[x], 16, 0)
// 		fmt.Printf("[%2d]  %10s%16s  %s\n", x, topKeys[x], intAsStringWithCommas(decNum), topNames[x])
// 	}
// }

func topReportByDate(title string) {
	fmt.Println(title)
	fmt.Println("POS  HEX DATE   -------------DATE------------   FILENAME")
	var decnum int64 = 0
	for x := 0; x < topDepth; x++ {
		decnum, _ = strconv.ParseInt(topKeys[x], 16, 0)
		t := time.Unix(decnum, 0)
		fmt.Printf("%2d:  %s%32s   %s\n", x+1, topKeys[x], t, topNames[x])
	}
}
