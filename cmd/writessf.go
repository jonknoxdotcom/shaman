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

// WriteSSF functions
// Will write records to a 'SHA Signature Format' file

type writeSSF struct {
	fwh  *os.File      // file write handle
	file *bufio.Writer // buffer writer

	tf int64 // total files (lines, i.e. records written)
	tb int64 // total bytes (of those lines written)

	nnew int64 // new records written     )
	nchg int64 // changed record written  ) count of record
	ndel int64 // deleted (dropped)       ) types written
	nunc int64 // unchanged               )

	dot       int   // dot ticker
	flushTime int64 // time of last buffer flush
}

// open(fn) opens file and sets buffers - an empty file means stdout.
func (writer *writeSSF) open(fileName string) error {
	// progress counters (for future, in case we launch two write sessions)
	writer.tf = 0
	writer.tb = 0
	writer.nnew = 0
	writer.nchg = 0
	writer.ndel = 0
	writer.nunc = 0
	writer.dot = 0

	if fileName != "" {
		// specified file = write to file (can fail)
		var err error
		writer.fwh, err = os.Create(fileName)
		if err != nil {
			return fmt.Errorf("Cannot create output file %s", fileName)
		}
		writer.file = bufio.NewWriterSize(writer.fwh, 64*1024)
	} else {
		// empty filename = write to stdout
		writer.file = bufio.NewWriterSize(os.Stdout, 512) // more 'real time'
	}
	flushTime = time.Now().Unix()
	return nil
}

// close() will flush and close file.
func (writer *writeSSF) close() {
	writer.file.Flush()
	writer.fwh.Close()
}

// writeSHA() is, in fact, minimalist string printer
func (writer *writeSSF) writeSHA(shab64 string) {
	fmt.Fprintln(writer.file, shab64)
}

// writeRecord() writes a record to the output file and generates explanations to stdout if enabled
// verbosity: 0=nothing, 1=dots, 2=explanation line for changes (for updates), 3=describe every write (for generates)
func (writer *writeSSF) writeRecord(amWriting bool, format int, verbosity int, tag string, shab64 string, modt string, size string, name string, flags string) {
	// fmt.Println("WRITING", tag, storeLine(name))
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
		fmt.Println("  " + storeLine(msg) + trail)
	}

	// pushing to output buffer
	if amWriting && tag != "D" {
		if shab64 == "" {
			// lazy hash
			_, shab64, _ = getFileSha256(name) // horrible - to be resolved
		}
		//fmt.Println(format)
		name = storeLine(name)
		switch format {
		case 1:
			// anonymise to SHA256 only
			fmt.Fprintln(writer.file, shab64)
		case 2:
			// anonymise to SHA256 + Modify time only
			fmt.Fprintln(writer.file, shab64+modt)
		case 3:
			// anonymise to SHA256 + Modify time + Size (full identifier) only
			fmt.Fprintln(writer.file, shab64+modt+size)
		case 4:
			// generate identifier + name (drop annotations)
			fmt.Fprintln(writer.file, shab64+modt+size+" :"+name)
		case 5:
			// full SSF record
			fmt.Fprintln(writer.file, shab64+modt+size+" :"+name)
		case 9:
			// md5sum compatibility mode
			shabin := shaBase64ToShaBinary(shab64)
			fmt.Fprintln(writer.file, fmt.Sprintf("%64x", shabin)+"  "+name)
		default:
			// 5+ - full SSF record
			abort(10, "Format not valid")
		}

		tf++
		tb += nbytes

		// flush control - every minute
		if time.Now().Unix() > flushTime+60 {
			//fmt.Println("Flushing output buffer!")
			writer.file.Flush()
			flushTime = time.Now().Unix()
		}
	}
}
