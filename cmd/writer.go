/*
Copyright © 2025 Jon Knox <jon@k2x.io>
*/
package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// ----------------------- Shared writer function -----------------------

// counters
var tf int64        // total files
var tb int64        // total bytes
var nnew int64      // new records written
var nchg int64      // changed record written
var ndel int64      // deleted (dropped)
var nunc int64      // unchanged
var dot int         // dot ticker
var flushTime int64 // time of last buffer flush

func writeInit(fnw string) *bufio.Writer {
	// progress counters (for future, in case we launch two write sessions)
	tf = 0
	tb = 0
	nnew = 0
	nchg = 0
	ndel = 0
	nunc = 0
	dot = 0

	// buffer
	var w *bufio.Writer // buffer writer (local!)
	if fnw != "" {
		// write to file
		//var err error
		fwh, err := os.Create(fnw)
		if err != nil {
			abort(4, "Cannot create file "+fnw)
		}
		w = bufio.NewWriterSize(fwh, 64*1024)
	} else {
		// write to stdout
		w = bufio.NewWriterSize(os.Stdout, 512) // more 'real time'
	}
	flushTime = time.Now().Unix()

	return w
}

// verbosity: 0=nothing, 1=dots, 2=explanation line
func writeRecord(w *bufio.Writer, amWriting bool, verbosity int, tag string, shab64 string, modt string, size string, name string, flags string) {
	// type and counters
	msg := ""
	trail := ""
	nbytes, _ := strconv.ParseInt(size, 16, 0) // assume good
	switch tag {
	case "N":
		msg = "  New: " + name
		nnew++
	case "C":
		msg = "  Chg: " + name
		nchg++
		if strings.Contains(flags, "T") {
			trail += " [Time]"
		}
		if strings.Contains(flags, "S") {
			trail += " [Size]"
		}
		if strings.Contains(flags, "H") {
			trail += " [Hash]"
		}
	case "U":
		// Unchanged
		msg = "  N/C: " + name
		nunc++
	case "V":
		// Verified unchanged (we checked the )
		msg = "  N/C: " + name + " (verified)"
		nunc++
	case "D":
		// Deleted - does not produce record
		msg = "  Del: " + name
		ndel++
	default:
		abort(10, "unknown tag")
	}

	// terminal report
	dot++
	switch true {
	case verbosity == 1 && (tag == "N" || tag == "C"):
		if dot%100 == 0 {
			fmt.Print(".")
		}
	case verbosity == 2 && tag != "U":
		if nbytes > 1*1024*1024 {
			trail += " (" + intAsStringWithCommas(int64(nbytes/(1024*1024))) + "MB)"
		}
		fmt.Println("  " + msg + trail)
	}

	// pushing to output buffer
	if amWriting && tag != "D" {
		if shab64 == "" {
			// lazy hash
			_, shab64 = getFileSha256(name) // horrible - to be resolved
		}
		fmt.Fprintln(w, shab64+modt+size+" :"+name)
		tf++
		tb += nbytes

		// flush control - every minute
		if time.Now().Unix() > flushTime+60 {
			//fmt.Println("Flushing output buffer!")
			w.Flush()
			flushTime = time.Now().Unix()
		}
	}
}
