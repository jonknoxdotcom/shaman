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
var topKeys []string  // that which we sort on
var topIdens []string // identifier block
var topNames []string // reporting name
var topDupes []int    // duplicate count
var topDupeUsed bool  // whether we use dupes
var topDepth int      // size of the table (N)

// set up topper (can be size or date)
func topInit(n int, useDupe bool, defaultKey string) {
	topDepth = n
	topKeys = make([]string, n)  // that which we sort on
	topIdens = make([]string, n) // identifier block
	topNames = make([]string, n) // reporting name
	topDupes = make([]int, n)    // duplicate count
	topDupeUsed = useDupe

	for x := 0; x < n; x++ {
		topKeys[x] = defaultKey
		topNames[x] = "(no entry)"
		topIdens[x] = ""
		topDupes[x] = 0
	}
}

func topAdd(key string, id string, name string) string {
	// do conditional dupes later

	// quickly check for duplication
	for x := 0; x < topDepth; x++ {
		if topIdens[x] == id {
			topDupes[x]++
			return topKeys[topDepth-1]
		}
	}

	// perform ascending insertion
	// fmt.Println("Want to insert", size, "into", sizes)
	pos := topDepth - 2 // "the row above the end of table"
	for pos >= 0 {
		// fmt.Print("CHK", size, "<", sizes[pos], " (pos=", pos, ")\n")

		if key <= topKeys[pos] { // <= required to get alpha on non-SHA search
			// fmt.Print("\n", "BREAK: ", size, "<", sizes[pos], " pos=", pos, "\n")
			break
		}

		// shift content down
		// fmt.Print("/ roll ", pos, "to", pos+1)
		topKeys[pos+1] = topKeys[pos]
		topNames[pos+1] = topNames[pos]
		topIdens[pos+1] = topIdens[pos]
		topDupes[pos+1] = topDupes[pos]
		pos--
	}

	// record insertion
	pos++
	// fmt.Printf("Insert %s at %d\n", size, pos)
	topKeys[pos] = key
	topNames[pos] = name
	topIdens[pos] = id
	topDupes[pos] = 1

	// return threshold (caller can reject without Adding)
	return topKeys[topDepth-1]
}

func topReportBySize(title string) {
	fmt.Println(title)
	fmt.Println("POS   HEX SIZE   -----SIZE-----   #  FILENAME")
	var decNum int64 = 0
	var lastNum int64 = 0
	for x := 0; x < topDepth; x++ {
		decNum, _ = strconv.ParseInt(topKeys[x], 16, 0)
		if !cli_ellipsis || decNum != lastNum {
			// print full line every time
			fmt.Printf("%2d:  %10s%16s %3d  %s\n", x+1, topKeys[x], intAsStringWithCommas(decNum), topDupes[x], topNames[x])
		} else {
			// use ellipsis to highlight repeated sizes/hashes
			fmt.Printf("%2d:  %10s%16s %3d  %s\n", x+1, "   ....   ", "....     ", topDupes[x], topNames[x])
		}
		lastNum = decNum
	}
}

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
