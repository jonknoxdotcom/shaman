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
)

// ----------------------- Shared writer function -----------------------

// write variables (globals)
var tf int64 // total files
var tb int64 // total bytes

var nnew int64 // new records written
var nchg int64 // changed record written
var ndel int64 // deleted (dropped)
var nunc int64 // unchanged

var dot int // dot ticker

var fwh *os.File

//var w *bufio.Writer

// func writeInit(w *bufio.Writer, fnw string) {
// 	fmt.Println("fnw=" + fnw)

// 	if fnw != "" {
// 		fmt.Println(w, "A")
// 		// write to file
// 		fwh, err := os.Create(fnw)
// 		if err != nil {
// 			abort(4, "Cannot create file "+fnw)
// 		}
// 		fmt.Println(w, "B")

// 		//w = bufio.NewWriterSize(fwh, 64*1024*1024)
// 		w = bufio.NewWriterSize(fwh, 64)
// 		fmt.Println(w, "C")

// 	} else {
// 		// write to stdout
// 		w = bufio.NewWriterSize(os.Stdout, 32) // more 'real time'
// 		fmt.Println(w, "D")
// 	}
// 	fmt.Println(w, "E")
// 	fmt.Println(w, "test of end write init")
// 	abort(0, "")
// }

// verbosity: 0=nothing, 1=dots, 2=explanation line
func writeRecord(w *bufio.Writer, amWriting bool, verbosity int, tag string, shab64 string, modt string, size string, name string, flags string) {

	///fmt.Println("writeRecord called ", amWriting, ",", verbosity, ",", tag, ",", shab64, ",", modt, ",", size, ",", name, ",", flags)
	// type and counters
	msg := ""
	trail := ""
	switch tag {
	case "N":
		msg = "  New: " + name
		nnew++
	case "C":
		msg = "  Chg: " + name
		nchg++
		if strings.Contains(flags, "M") {
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
		// Deleted
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
		fmt.Println("  " + msg + trail)
	}

	// pushing to output buffer
	if amWriting {
		if shab64 == "" {
			// lazy hash
			_, shab64 = getFileSha256(name) // horrible - to be resolved
		}
		fmt.Fprintln(w, shab64+modt+size+" :"+name)
		tf++
		nbytes, _ := strconv.ParseInt(size, 16, 0) // assume good
		tb += nbytes

		// flush control
		//fmt.Println("Totals:", tf, tb)
		if tf%500 == 0 {
			fmt.Println("Flushing output buffer")
			w.Flush()
		}
	}
}
