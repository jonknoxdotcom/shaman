/*
Copyright © 2025 Jon Knox <jon@k2x.io>
*/
package cmd

import (
	"bufio"
	"log"
	"log/slog"
	"os"
	"strings"

	"github.com/fsnotify/fsnotify"
	"github.com/spf13/cobra"

	"fmt"
)

// -------------------------------- Cobra management -------------------------------

// detectCmd represents the detect command
var detectCmd = &cobra.Command{
	Use:   "detect [file.ssf...] [-p path] [-c checkport] ",
	Short: "Detect exfiltrated files",
	Long: `shaman detect
Detect files in monitored folders.  Supply one or more SSF files to provide signatures of
watched-for files.  Will run check of environment by default to see it contains no watched
files. Then will continue to monitor for new files and perform checks on them.  Program 
runs without exit unless detection successful. Alternatively, HTTP port provides status
via HTTP 200 (all clean) and HTTP 503 (unhealthy - detected banned content). Side note:
we avoid HTTP 404 to indicate failure as 'not found' might be misconstrued as 'clean'.
To avoid false positives, the HTTP server does not start until the monitor phase starts.`,
	Aliases: []string{"det"},
	Args:    cobra.MaximumNArgs(99),
	GroupID: "G1",
	Run: func(cmd *cobra.Command, args []string) {
		det(args)
	},
}

func init() {
	rootCmd.AddCommand(detectCmd)

	detectCmd.Flags().StringVarP(&cli_path, "path", "p", "", "Path to directory to monitor (default is current directory)")
	detectCmd.Flags().IntVarP(&cli_check, "check", "c", 0, "Check port (HTTP200/500 health-check endpoint) - over-rides exit")
	detectCmd.Flags().BoolVarP(&cli_verbose, "verbose", "v", false, "Give running commentary of detect")
	detectCmd.Flags().BoolVarP(&cli_nodot, "no-dot", "", false, "Ignore files/directories beginning '.'")
	detectCmd.Flags().BoolVarP(&cli_asap, "asap", "", false, "Give up as soon as error detected (when speed is of the essence)")
	detectCmd.Flags().BoolVarP(&cli_noprecheck, "no-precheck", "", false, "Used to disable to pre-check that the environment is clean")
}

// ----------------------- Detect function below this line -----------------------

// "shaman det" runs in a closed loop and does not exit unless the detection is successful
// Detect takes a single parameter which is an SSF containing files to be detected (can be format 1 - i.e. anonymous)
// The contents of the file are read in and stored (as binary 32-bit SHA256 hashes only) called the watchlist
// The filesystem from the CWD (or from a --path directive) is scanned ("monitor directory")
// All files are hashed and compared against the watchlist
// An immediate termination occurs if a match is found
// The application now enters watch mode, waiting for new files to be added to the monitor directory
// All new files are hashed and compared to the watchlist, and the application exits if a match is found
// If the optional "-c" health check endpoint is used at start, then an HTTP listener is generated
// The application then does not exit but returns a 200 or 500 depending on a clean or detected state

// Phase 1 - read watchlist
// Phase 2 - scan monitor directory
// Phase 3 - listen for changes

// shaman latest.ssf -c 80  --skip  && add --HUP stuff

func det(args []string) {
	// process CLI
	num, files, found := getSSFs(args)
	slog.Debug("cli handler", "num", num, "files", files, "found", found)
	switch true {
	case num > 10:
		abort(8, "Too many watchlists")
	case num < 1:
		abort(9, "Watch list (.ssf) not specified")
	}

	// Key variables
	watchedFileDetected := false               // watched files - for precheck and monitor phases
	watchedSHAs := make(map[binsha]bool, 1000) // stored binary SHAs

	// Phase 1 - get watch list from cli and ingest as binary
	if cli_verbose {
		fmt.Println("Phase 1 - establishing watch list")
	}

	// ingest SHAs
	for i := range num {
		if !found[i] {
			fmt.Printf("Signature file '%s' not found\n", files[i])
			continue
		}

		if cli_verbose {
			fmt.Printf("Reading %s...\n", files[i])
		}

		var r *os.File
		r, err := os.Open(files[i])
		if err != nil {
			fmt.Printf("Signature file '%s' cannot be read (check permissions)\n", files[i])
			continue
		}
		defer r.Close()

		lineno := 0 // local file line number
		scanner := bufio.NewScanner(r)
		for scanner.Scan() {
			// process the line from scanner (from the SSF file)
			s := scanner.Text()
			lineno++

			// drop comments or empty lines
			if len(s) == 0 || s[0:1] == "#" {
				continue
			}

			// drop wrong length lines
			if len(s) < 43 {
				fmt.Printf("Ignoring line %d - not a signature\n", lineno)
				ndel++
				continue
			}

			// add sha to watch list
			shaBase64 := string(s[0:43])
			var key binsha = binsha(shaBase64ToShaBinary(shaBase64))
			watchedSHAs[key] = true
		}

	}
	if len(watchedSHAs) == 0 {
		abort(1, "Nothing to detect (watch list is empty)")
	}
	if cli_verbose {
		fmt.Printf("Watch list has %d signatures\n", len(watchedSHAs))
	}

	// Phase 2 - scan the cwd (or path)
	if !cli_noprecheck {
		if cli_verbose {
			fmt.Println("Phase 2 - scanning existing file space")
		}

		// Call the tree walker to generate a file list (as a channel)
		var startpath string = "."
		if cli_path != "" {
			startpath = cli_path // add validation here
		}
		fileQueue := make(chan triplex, 4096)
		go func() {
			defer close(fileQueue)
			walkTreeToChannel(startpath, fileQueue)
		}()

		var total_files int
		for filerec := range fileQueue {
			// drop if files or directories begins "." and nodot asserted
			if cli_nodot && (strings.Contains(filerec.filename, "/.") || filerec.filename[0:1] == ".") {
				continue
			}

			sha_bin, _, _ := getFileSha256(filerec.filename)

			_, is_watched := watchedSHAs[sha_bin]
			if is_watched {
				fmt.Fprintf(os.Stderr, "Detected file: %s\n", filerec.filename)
				watchedFileDetected = true
				if cli_asap {
					break
				}
			}

			total_files++
		}
		if watchedFileDetected && cli_check == 0 {
			abort(1, "One or more watched files already present")
		}
		fmt.Printf("Scanned %d files - no problems\n", total_files)
	}
	if cli_noprecheck && cli_verbose {
		fmt.Println("Skipping phase 2 (pre-check)")
	}

	// Phase 3: watch directories
	if cli_verbose {
		fmt.Println("Phase 3 - monitoring directories")
	}

	// Create new watcher.
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatal(err)
	}
	defer watcher.Close()

	// File system monitoring
	go func() {
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				fmt.Println("event:", event)
				if event.Has(fsnotify.Write) {
					fmt.Println("modified file:", event.Name)
				}
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				fmt.Println("error:", err)
			}
		}
	}()

	// Add a path.
	err = watcher.Add("/Users/jon/Code/shaman/test")
	if err != nil {
		// fmt.Fatal(err)
	}
	err = watcher.Add("/tmp")
	if err != nil {
		// fmt.Fatal(err)
	}

	// (Optionally) stand up HTTP health-check server here

	// Block main goroutine forever.
	<-make(chan struct{})
}
