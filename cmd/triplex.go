/*
Copyright © 2025 Jon Knox <jon@k2x.io>
*/
package cmd

import (
	"fmt"
	"os"
	"path"
)

// ----------------------- Triplex read channel handlers -----------------------

// The read queue is channel based
// It serves a file entity as a 3-tuple
// The three values that it dispenses (name, modttime, size)
// It used hex (0x) values rather than excess type conversion
// It's called the "triplex" channel for this reasons

// ----------------------- Directory traversal (producer)

type triplex struct {
	filename string
	modified int64
	size     int64
}

func walkTreeToChannel(startpath string, c chan triplex) {
	entries, err := os.ReadDir(startpath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Skipping directory: %s\n", startpath)
		return
	}

	// step through contents of this dir
	for _, entry := range entries {
		if !entry.IsDir() {
			if !entry.Type().IsRegular() {
				// we ignore symlinks
				continue
			}

			name := path.Join(startpath, entry.Name())
			info, err := entry.Info()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Skipping file: %s\n", name)
				continue
			}

			c <- triplex{name, info.ModTime().Unix(), info.Size()}
		} else {
			// it's a directory - dig down
			walkTreeToChannel(path.Join(startpath, entry.Name()), c)
		}
	}
}

// ----------------------- Directory traversal (producer)

//var fileQueue = chan triplex

// func setTriplex(fileQueue chan triplex, startpath string) {

// 	fileQueue = make(chan triplex, 4096)
// 	go func() {
// 		defer close(fileQueue)
// 		walkTreeToChannel(startpath, fileQueue)
// 	}()
// }

func getNextTriplex(fileQueue chan triplex) (fs_name string, fs_modt string, fs_size string) {
	t, ok := <-fileQueue
	///fmt.Println(t)
	if !ok {
		return "", "", ""
	} else {
		return t.filename,
			fmt.Sprintf("%08x", t.modified), // always 8 digits
			fmt.Sprintf("%04x", t.size) // overflows 4-8 digits
	}
}
