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

// readSSF functions
// Will read and unpack lines from a 'SHA Signature File' formatted file

type readSSF struct {
	scanner       *bufio.Scanner // Buffered IO reader
	file          *os.File       // Handle to open file being processed
	trackingLine  int64          // Line number of last read line
	shaBase64     string         // SHA of last valid line
	buffer        string         // Copy of last valid line
	format        int            // Format, as defined in consts (above)
	spacePosition int            // carried first " " position (if checked)
	spaceColon    int
	name          string
}

// open is used to establish the read channel for the SSF file if viable.
// An error is returned if the file is not found or it is inaccessible due to permission problems
func (reader *readSSF) open(fileName string) error {
	f, err := os.Open(fileName)
	if err != nil {
		return err
	}
	reader.file = f
	reader.scanner = bufio.NewScanner(f)
	reader.trackingLine = 0
	reader.format = FormatUndefined
	return nil
}

// close is used to tidyly shut down a reader operation.
func (reader *readSSF) close() {
	reader.file.Close()
}

// nextSHA consumes lines from the input file until a new valid line is reached. It returns the SHA and probable format of this line.
// It is a quick partial decode/validation. The line number in the file is tracked, so that errors can describe failed lines.
// This routine is optimised to fail quickly if fed a file that is not an SSF.  Use allField or allValues for next stage extraction.
func (reader *readSSF) nextSHA() (shab64 string, format int, lineNumber int64, err error) {
	reader.buffer = ""
	reader.shaBase64 = "" // required in case file empty
	reader.format = FormatUndefined

	for reader.scanner.Scan() {
		// process the line from scanner (from the SSF file)
		s := reader.scanner.Text()
		reader.trackingLine++

		// drop comments or empty lines and try again
		if len(s) == 0 || s[0:1] == "#" {
			continue
		}

		// check for sufficient line to check for SHA / validate SHA characters
		if len(s) < 43 || !isBase64(s[0:43]) {
			// must be a bad line - too short or not right characters (caller likely to abort read)
			return "", -1, reader.trackingLine, fmt.Errorf("invalid format #1")
		}

		// looks like a valid hash - store the values for fullExtract()
		reader.buffer = s
		reader.shaBase64 = s[0:43]

		// just the hash is fine
		if len(s) == 43 {
			// format 1: just SHA
			reader.format = FormatSha
			return reader.shaBase64, reader.format, reader.trackingLine, nil
		}

		// rest of initial field should be hex
		pos := strings.IndexByte(s, 32)
		reader.spacePosition = pos
		if pos == -1 {
			// there's no annotation or name
			hexStream := s[43:]
			if !isHexadecimal(hexStream) {
				return "", -1, reader.trackingLine, fmt.Errorf("invalid format #2")
			}
			if len(hexStream) == 8 {
				// format 2: just SHA+modtime
				reader.format = FormatShaMod
				return reader.shaBase64, reader.format, reader.trackingLine, nil
			}
			if len(hexStream) >= 12 && len(hexStream) <= 22 {
				// format 3: just SHA+modtime+size
				reader.format = FormatShaModSize
				return reader.shaBase64, reader.format, reader.trackingLine, nil
			}
			return "", -1, reader.trackingLine, fmt.Errorf("invalid format #3")
		} else {
			// there's a space after the presumed hex
			hexStream := s[43:pos]
			// fmt.Println("[" + hexStream + "]")
			if len(hexStream) >= 12 && len(hexStream) <= 22 {
				// format 5: just SHA+modtime+size
				if s[pos+1:pos+2] != ":" {
					reader.format = FormatShaModSizeAnnot
				} else {
					reader.format = FormatAll
				}
				return reader.shaBase64, reader.format, reader.trackingLine, nil
			}
			return "", -1, reader.trackingLine, fmt.Errorf("invalid format #4")
		}
	}

	// break out (Scan failed) - give an empty string
	return "", -1, reader.trackingLine, nil
}

// allFields returns the values of the last validly read line from the SSF file.
// The fields are in the stored format - i.e. sha-base64 for SHA256, and hexadecimal for mod-time and byte-size.
// This is the quicker function for rapid mass triage.  Name is not restored.
// This could be made DRYer, but it wouldn't be as quick...
func (reader *readSSF) allFields() (shab64 string, format int, modtime string, length string, name string, annotations []string, err error) {
	switch reader.format {
	case FormatSha:
		// only SHA present
		return reader.shaBase64, reader.format, "", "", "", []string{}, nil
	case FormatShaMod:
		// SHA and simple 8ch hex time
		modTime := reader.buffer[43:51]
		return reader.shaBase64, reader.format, modTime, "", "", []string{}, nil
	case FormatShaModSize:
		// SHA, simple 8ch hex time, and 4-10ch hex size
		modTime := reader.buffer[43:51] // 8ch hex
		sizeBytes := reader.buffer[51:]
		return reader.shaBase64, reader.format, modTime, sizeBytes, "", []string{}, nil
	case FormatShaModSizeAnnot:
		// As above, plus annotations but no name
		modTime := reader.buffer[43:51] // 8ch hex
		sizeBytes := reader.buffer[51:reader.spacePosition]
		// extract annotation here *FIXME*
		return reader.shaBase64, reader.format, modTime, sizeBytes, "", []string{}, nil
	case FormatAll:
		// SHA, 8ch time, 4-10ch size, annots, name
		modTime := reader.buffer[43:51]
		sizeBytes := reader.buffer[51:reader.spacePosition]
		// extract annotation here *FIXME*
		pos2 := strings.Index(reader.buffer, " :")
		reader.spaceColon = pos2
		if pos2 == -1 {
			return reader.shaBase64, reader.format, "", "", "", []string{}, fmt.Errorf("unexpected absent name field")
		}
		reader.name = reader.buffer[pos2+2:]
		return reader.shaBase64, reader.format, modTime, sizeBytes, reader.name, []string{}, nil

	default:
		return reader.shaBase64, reader.format, "", "", "", []string{}, fmt.Errorf("invalid call to allFields")
	}

	//return reader.shaBase64, 5, "68b482da", "0006", "file.jpg", []string{"P800x600", "Fjpg"}
}

// allValues is similar to allFields() except it translate field format into native format for the values.
// The sha is in the smaller binary form, the mod-time and size are int64s, and the annotations are separated
func (reader *readSSF) allValues() (sha binsha, format int, modtime int64, length int64, name string, annotations []string) {
	return shaBase64ToShaBinary(reader.shaBase64), 5, 1756660442, 6, "file.jpg", []string{"P800x600", "Fjpg"}
}
