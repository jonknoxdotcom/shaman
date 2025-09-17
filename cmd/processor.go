/*
Copyright © 2025 Jon Knox <jon@k2x.io>
*/
package cmd

import (
	"fmt"
	"os"
	"strconv"
)

// Processor functions
// SSF processor - handle file and SSF streams using callbacks
//

// How it works:
// The SSF processor has three types of data sources:
// a) a streamed file ("file")                ) unlimited in size
// b) a streams file system read ("path")     )
// c) a file converted into a map ("shamap")  - limited to memory size (1,000,000 records is fine)

// Processor methods:
// e             = open(fn) - open an SSF file (underlying, this will be a file open) / opens, read to read records
// e             = path(pn) - open a path (underlying this will be a triplex channel) / just checks it exists
// m,fn,fs,e     = mapper(fn,type) - returns go map with key=hash, type=meta|none
// fn,fd,fs,e    = fsize() - return size info on file (as lone operation) - size excludes any anon 'dropped' records
// fn,fs,e       = psize() - return size info on path (as lone operation)
// fn,fs,fn,fs,e = compare(*g,*w) - compare file vs path, using callbacks get and write (shallow then deep)
// NB: almost everything returns a record count and size (fn,fs)

type processSSF struct {
	reader *readSSF // reader object
	fNoDot bool     // file no-dot dropper - whether to exclude files/paths beginning '.'
	fLine  int64    // file line counter - line in file as opposed to record count
	fName  string   // stored filename

	pName     string       // pathname to where start tree-walk
	fileQueue chan triplex // generated queue of files to process
}

// open(fn) - open an SSF file (all the checks that it exists as well), handle to fileRead
func (p *processSSF) fread(fileName string, nodot bool) error {
	p.reader = new(readSSF)
	p.fNoDot = nodot
	p.fLine = 0
	p.fName = fileName

	return p.reader.open(fileName, nodot)
}

// close() - closes all open files (read or write)
func (p *processSSF) close() {
	if p.fName != "" {
		p.reader.close()
	}
	// if p.fileNameWrite != "" {
	// 	close(p.fileWrite)
	// }
}

// TEMP
// func pathExists(path string) (bool, error) {
// 	_, err := os.Stat(path)
// 	if err == nil {
// 		return true, nil
// 	}
// 	if errors.Is(err, fs.ErrNotExist) {
// 		return false, nil
// 	}
// 	return false, err
// }

// path(pn) - open a path (underlying this will be a triplex channel) / just checks it exists
func (p *processSSF) path(pathName string, nodot bool) error {

	// sort out a pathname to walk (don't expect blank)
	if pathName == "" {
		pathName = "."
	}
	p.pName = pathName
	_, err := os.Stat(pathName)
	if err != nil {
		// almost certainly will be an "errors.Is(err, fs.ErrNotExist)"
		return err
	}

	// parallel tree walker - producer
	return p.preset(nodot)
}

// preset() generates a walking list for the path
func (p *processSSF) preset(nodot bool) error {
	// parallel tree walker - producer
	p.fileQueue = make(chan triplex, 4096)
	go func() {
		defer close(p.fileQueue)
		walkTreeYieldFilesToChannel(p.pName, p.fileQueue, nodot)
	}()
	return nil
}

// mapper(fn,type) - returns go map with key=hash, type=meta|none
func (p *processSSF) mapper(pathName string) error {
	return nil
}

// fsize() - return size info on file (as lone operation)
// The file must have been already opened with open().
func (p *processSSF) fsize() (int64, int64, int64, error) {
	// ensure at start of file
	p.reader.reset()

	// this is the return order
	var fTotalFiles int64
	var fTotalDropped int64
	var fTotalBytes int64

	var shab64 string
	var err error // error object
	var errorTolerance int = 5
	var lineno int64 // needed for error reporting on .ssf file corruptions
	var format int
	var length string

	for true {
		// perform minimal fetch, err for bad files, no err + empty sha means exhaustion
		shab64, format, lineno, err = p.reader.nextSHA() // shab64, format, lineNumber, line, err
		p.fLine++

		// golden path - store lines and go again
		if shab64 != "" {
			// add to counts
			fTotalFiles++

			if format >= 3 {
				// add bytes
				_, _, _, length, _, _, err = p.reader.allFields()
				nbytes, _ := strconv.ParseInt(length, 16, 0)
				fTotalBytes += nbytes
			} else {
				fTotalDropped++
			}
			continue
		}

		// infrequent - allow a small number of misformed lines before giving up
		if err != nil {
			errorTolerance--
			if errorTolerance < 0 {
				return 0, 0, 0, fmt.Errorf("Too many errors reading %s - giving up", p.fName)
			}
			fmt.Printf("Error: ignoring line %d of %s - %s\n", lineno, p.fName, err)
			continue
		}

		// infrequent - eof detect
		if shab64 == "" {
			break
		}
	}

	return fTotalFiles, fTotalDropped, fTotalBytes, nil
}

// psize() - return size info on path (as lone operation)
func (p *processSSF) psize() (int64, int64, error) {
	var tf int64 // total number of files
	var ts int64 // total size in bytes
	if p.fileQueue == nil {
		return 0, 0, fmt.Errorf("Internal error - queue not configured")
	}
	for true {
		fileName, _, fileLength := getNextTriplexRaw(p.fileQueue)
		if fileName == "" {
			return tf, ts, nil
		}

		tf++
		ts += fileLength
	}
	return 0, 0, nil // dummy
}

// function signatures of custom functions
type compGetter func(fn string, size int64) string
type compWriter func(form int, tag string, modt string, size string, name string) error

// compare(*g,*w, shallow) - compare file vs path, using callbacks get and write
func (p *processSSF) compare(fngetSHA compGetter, fnWriteRecord compWriter, shallow bool) (int64, int64, int64, int64, error) {

	// this is a dummy to test function control
	var tf int64 // total number of files
	var ts int64 // total size in bytes

	p.preset(false)

	if p.fileQueue == nil {
		return 0, 0, 0, 0, fmt.Errorf("Internal error - queue not configured")
	}
	for true {
		fileName, _, fileLength := getNextTriplexRaw(p.fileQueue)
		if fileName == "" {
			return tf, ts, 0, 0, nil
		}

		tf++
		ts += fileLength
		_ = fngetSHA(fileName, fileLength)
	}

	return 0, 0, 0, 0, nil // dummy
}
