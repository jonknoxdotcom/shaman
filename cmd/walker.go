/*
Copyright © 2025 Jon Knox <jon@k2x.io>
*/
package cmd

import (
	"fmt"
	"os"
	"time"
)

// ----------------------- Walker - manage directory walking -----------------------

type walkTree struct {
	pName      string       // the path
	nodot      bool         // follow dot files/dirs?
	startTime  int64        // Unixtime when we started (milli)
	lastUpdate int64        // Unixtime of last file/byte update (milli)
	nFiles     int64        // files processed so far
	nBytes     int64        // bytes processed so far
	nFilesAll  int64        // nFiles at end
	nBytesAll  int64        // nBytes at end
	fileQueue  chan triplex // parallel file queue
}

func (w *walkTree) setProgress(tf int64, tb int64) {
	w.nFiles = tf
	w.nBytes = tb
	w.lastUpdate = time.Now().UnixMilli()
}

func (w *walkTree) getProgress() (int64, int64, int64, int64, int64, error) {
	if w.pName == "" {
		return 0, 0, 0, 0, 0, fmt.Errorf("No path")
	} else {
		return w.nFiles, w.nBytes, w.nFilesAll, w.nBytesAll, w.lastUpdate - w.startTime, nil
	}
}

// path(pn) - open a path (underlying this will be a triplex cxannel) / just checks it exists
func (w *walkTree) path(pathName string, nodot bool) error {

	// sort out a pathname to walk (don't expect blank)
	if pathName == "" {
		pathName = "."
	}
	w.pName = pathName
	_, err := os.Stat(pathName)
	if err != nil {
		// almost certainly will be an "errors.Is(err, fs.ErrNotExist)"
		return err
	}

	// parallel tree walker - producer
	return w.preset(nodot)
}

// preset() generates a walking list for the path
func (w *walkTree) preset(nodot bool) error {
	// parallel tree walker - producer
	w.fileQueue = make(chan triplex, 4096)
	w.startTime = time.Now().UnixMilli()
	go func() {
		defer close(w.fileQueue)
		walkTreeYieldFilesToChannel(w.pName, w.fileQueue, nodot)
	}()
	return nil
}

// psize() - return size info on path (as lone operation)
func (w *walkTree) psize() (int64, int64, error) {
	var tf int64 // total number of files
	var ts int64 // total size in bytes
	if w.fileQueue == nil {
		return 0, 0, fmt.Errorf("Internal error - queue not configured")
	}
	for true {
		fileName, _, fileLength := getNextTriplexRaw(w.fileQueue)
		if fileName == "" {
			w.nFilesAll = tf
			w.nBytesAll = ts
			return tf, ts, nil
		}

		tf++
		ts += fileLength
	}
	return 0, 0, nil // dummy
}
