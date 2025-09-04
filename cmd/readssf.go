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

const (
	FormatSha             int = 1 // SHA as truncated base64
	FormatShaMod          int = 2 // add: modify time as hex epoch time
	FormatShaModSize      int = 3 // add: size as hex in bytes
	FormatShaModSizeAnnot int = 4 // add: annotations (multiple)
	FormatAll             int = 5 // add: name (default shaman format)
	FormatCSV             int = 6 // Comma-separated hex SHA, decimal time+size  )
	FormatNativeBSDOSX    int = 7 // BSD/OSX format SHA256 output	             ) output
	FormatNativeOpenSSL   int = 8 // OpenSSL format SHA256 output	             ) only
	FormatNativeLinux     int = 9 // Linux format SHA256 output		             )
)

// readSSF functions
// Will read and unpack lines from a 'SHA Signature File' formatted file

type readSSF struct {
	scanner      *bufio.Scanner
	file         *os.File
	trackingLine int64
	shaBase64    string
	buffer       string
}

// open is used to establish the read channel for the SSF file if viable.
// An error is returned if the file is not found or it is inaccessible due to permission problems
func (reader *readSSF) open(fileName string) error {
	f, err := os.Open(fileName)
	if err != nil {
		return err
	}
	reader.file = f
	reader.trackingLine = 0
	reader.shaBase64 = ""
	reader.scanner = bufio.NewScanner(f)
	return nil
}

// close is used to tidyly shut down a reader operation.
func (reader *readSSF) close() {
	reader.file.Close()
}

// nextLine takes a scanner file and returns the next record's SHA + undecoded line. It also tracks line number.
// The returned line will have valid base64 and hex (if present) in all the right places. It may be format 1,2,3,4,5.
// The tracking line number is always returned, and can be relied upon and quoted in an error message if required.
// This routine is optimised to fail quickly if fed a file that is not SSF.
func (reader *readSSF) nextLine() (shab64 string, format int, lineNumber int64, line string, err error) {
	reader.buffer = ""
	for reader.scanner.Scan() {
		// process the line from scanner (from the SSF file)
		s := reader.scanner.Text()
		reader.trackingLine++

		// drop comments or empty lines
		if len(s) == 0 || s[0:1] == "#" {
			continue
		}

		// check for sufficient line to check for SHA / validate SHA characters
		if len(s) < 43 || !isBase64(s[0:43]) {
			// must be a bad line - too short or not right characters (caller likely to abort read)
			return "", -1, reader.trackingLine, "", fmt.Errorf("invalid format #1")
		}

		// looks like a valid hash - store the values for fullExtract()
		reader.buffer = s
		reader.shaBase64 = s[0:43]

		// just the hash is fine
		if len(s) == 43 {
			// format 1: just SHA
			return s[0:43], FormatSha, reader.trackingLine, s, nil
		}

		// rest of initial field should be hex
		pos := strings.IndexByte(s, 32)
		if pos == -1 {
			// there's no annotation or name
			hexStream := s[43:]
			if !isHexadecimal(hexStream) {
				return "", -1, reader.trackingLine, "", fmt.Errorf("invalid format #2")
			}
			if len(hexStream) == 8 {
				// format 2: just SHA+modtime
				return s[0:43], FormatShaMod, reader.trackingLine, s, nil

			}
			if len(hexStream) >= 12 && len(hexStream) <= 22 {
				// format 3: just SHA+modtime+size
				return s[0:43], FormatShaModSize, reader.trackingLine, s, nil

			}
			return "", -1, reader.trackingLine, "", fmt.Errorf("invalid format #3")

		} else {
			// there's a space after the presumed hex
			hexStream := s[43:pos]
			// fmt.Println("[" + hexStream + "]")
			if len(hexStream) >= 12 && len(hexStream) <= 22 {
				// format 5: just SHA+modtime+size
				if s[pos+1:pos+2] != ":" {
					return s[0:43], FormatShaModSizeAnnot, reader.trackingLine, s, nil
				} else {
					return s[0:43], FormatAll, reader.trackingLine, s, nil
				}
			}
			return "", -1, reader.trackingLine, "", fmt.Errorf("invalid format #4")
		}
	}

	// fall out (Scan failed) - give an empty string
	return "", -1, reader.trackingLine, "", nil
}

// allFields returns the values of the last validly read line from the SSF file.
// The fields are in the stored format - i.e. sha-base64 for SHA256, and hexadecimal for mod-time and byte-size.
func (reader *readSSF) allFields() (shab64 string, format int, modtime string, length string, name string, annotations []string) {
	return reader.shaBase64, 5, "68b482da", "0006", "file.jpg", []string{"P800x600", "Fjpg"}
}

// allValues is similar to allFields() except it translate field format into native format for the values.
func (reader *readSSF) allValues() (sha binsha, format int, modtime int64, length int64, name string, annotations []string) {
	return shaBase64ToShaBinary(reader.shaBase64), 5, 1756660442, 6, "file.jpg", []string{"P800x600", "Fjpg"}
}
