/*
Copyright © 2025 Jon Knox <jon@k2x.io>
*/
package cmd

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
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
// fn,fs,e       = fsize() - return size info on file (as lone operation)
// fn,fs,e       = psize() - return size info on path (as lone operation)
// fn,fs,fn,fs,e = compare(*g,*w) - compare file vs path, using callbacks get and write (shallow then deep)
// NB: almost everything returns a record count and size (fn,fs)

type processSSF struct {
	streamOrigin  string
	streamChannel chan triplex
	fileNameRead  string
	fileRead      *os.File
	nodotRead     bool

	lineRead      int
	fileNameWrite string
	fileWrite     *os.File
	lineWrite     int

	scanner      *bufio.Scanner // Buffered IO reader
	trackingLine int64          // Line number of last read line

	fileQueue chan triplex
}

// open(fn) - open an SSF file (all the checks that it exists as well), handle to fileRead
func (process *processSSF) open(fileName string, nodot bool) error {
	f, err := os.Open(fileName)
	if err != nil {
		return err
	}
	process.fileRead = f
	process.fileNameRead = fileName
	process.lineRead = 0
	process.nodotRead = nodot
	return nil
}

// close() - closes all open files (read or write)
func (process *processSSF) close() error {
	// if process.fileNameRead != "" {
	// 	close(process.fileRead)
	// }
	// if process.fileNameWrite != "" {
	// 	close(process.fileWrite)
	// }
	return nil
}

// TEMP
func pathExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	return false, err
}

// path(pn) - open a path (underlying this will be a triplex channel) / just checks it exists
func (process *processSSF) path(pathName string, nodot bool) error {

	// sort out a pathname to walk (don't expect blank)
	if pathName == "" {
		pathName = "."
	}
	_, err := os.Stat(pathName)
	if err != nil {
		// almost certainly will be an "errors.Is(err, fs.ErrNotExist)"
		return err
	}

	// parallel tree walker - producer
	process.fileQueue = make(chan triplex, 4096)
	go func() {
		defer close(process.fileQueue)
		walkTreeYieldFilesToChannel(pathName, process.fileQueue, nodot)
	}()

	return nil
}

// mapper(fn,type) - returns go map with key=hash, type=meta|none
func (process *processSSF) mapper(pathName string) error {
	return nil
}

// fsize() - return size info on file (as lone operation)
func (process *processSSF) fsize() (int64, int64, error) {
	// ensure at start of file
	process.fileRead.Seek(0, io.SeekStart)

	// scan := new(readSSF)
	// if scan.open(process.fileRead) != nil {
	// 	abort(4, "internal error unable to start seeking on file read handle")
	// }
	// defer scan.close()

	return 0, 0, nil
}

// psize() - return size info on path (as lone operation)
func (process *processSSF) psize() (int64, int64, error) {
	var tf int64 // total number of files
	var ts int64 // total size in bytes
	if process.fileQueue == nil {
		return 0, 0, fmt.Errorf("Internal error - queue not configured")
	}
	for true {
		fileName, _, fileLength := getNextTriplexRaw(process.fileQueue)
		tf++
		ts += fileLength
		if fileName == "" {
			return tf, ts, nil
		}
	}
	return 0, 0, nil // dummy
}

// function signatures of custom functions
type compGetter func(fn string, size int64) string
type compWriter func(form int, tag string, modt string, size string, name string) error

// compare(*g,*w) - compare file vs path, using callbacks get and write
func (process *processSSF) compare(fngetSHA compGetter, fnWriteRecord compWriter, shallow bool) (int64, int64, int64, int64, error) {
	return 0, 0, 0, 0, nil
}
