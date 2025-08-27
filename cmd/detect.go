/*
Copyright © 2025 Jon Knox <jon@k2x.io>
*/
package cmd

import (
	"bufio"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/spf13/cobra"
)

// -------------------------------- Cobra management -------------------------------

// detectCmd represents the detect command
var detectCmd = &cobra.Command{
	Use:   "detect [file.ssf...] [-p path] [-c checkport] ",
	Short: "Detect exfiltrated files",
	Long: `shaman detect
Detect files in monitored folders.  Supply one or more SSF files to provide signatures of
watched-for files.  Will run check of environment by default to see it contains no watched
files. Then will continue to monitor for newly deposited files and perform checks on them.
Program loops until detection successful. Alternatively, HTTP port provides status via 
HTTP 200 (all clean) and HTTP 503 (unhealthy - detected banned content). Note: we avoid
returning 404 to indicate failure as 'not found' might be misconstrued as 'clean'. 
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
	detectCmd.Flags().BoolVarP(&cli_disclose, "disclose", "", false, "Add time-series disclosure to health-check '/log' endpoint")
}

// ----------------------- Detect function below this line -----------------------

// "shaman det" keeps a directory tree free from "watched-for" files
// It runs in a closed loop and does not exit unless a detection is successful
//
// Phase 1 - populate watchlist
// Takes a one or more SSF filenames which list the files to be "watched-out-for" (this can be anon '--format 1')
// The SHA parts of the file are read and stored densely as binary 32-bit SHA256 hashes in the 'watchlist'
//
// Phase 2 - scan monitored directory
// The filesystem from the CWD (or from a '--path' directive) is scanned ("monitor directory")
// All files are hashed and compared against the watchlist
// An immediate termination occurs if a match is found
//
// Phase 3 - listen for changes
// The application now enters watch mode, waiting for new files to be added to the monitor directory
// All new files are hashed and compared to the watchlist, and the application exits if a match is found
// If the optional "-c" health check endpoint is used at start, then an HTTP listener is generated
// The application then does not exit but returns a 200 or 500 depending on a clean or detected state

// Examples
// shaman latest.ssf                # scan current dir, then listen and return rc=1 on detection
// shaman latest.ssf --asap         # do not list all pre-flight detection failures, just the first one
// shaman latest.ssf --no-precheck  # skip the initial scan of the tree
// shaman latest.ssf -c 80          # present detection via an HTTP health endpoint (no exit)
// kill -HUP $SHAMANPID             # reload SSF file after a change

// Next steps:
// * add trigger abstraction, collect hits
// * record time-series event data
// * add HUP reload handling
// * prometheus endpoint??

var watcher *fsnotify.Watcher   // handle to notification library
var watchedFileDetected bool    // flag for true positive
var watchedSHAs map[binsha]bool // watch list map

// time-series recordings of detection events
type detectionTS struct {
	timeStamp     int64  // unixtime detected
	duringPrescan bool   // phase of discovery
	fileName      string // name of file
	sha           binsha // identified (SHA,modtime,size)
}

var watchDetected []detectionTS // list of discovered violations

func tsLogger(t int64, pre bool, fileName string, sb binsha) {
	watchDetected = append(watchDetected, detectionTS{t, pre, fileName, sb})
}

// watchLoop runs as a go-routine to process filesystem events such as creating new files or directories.
func watchLoop(w *fsnotify.Watcher) {
	// i := 0
	for {

		select {
		// Read from Errors.
		case err, ok := <-w.Errors:
			if !ok { // Channel was closed (i.e. Watcher.Close() was called).
				return
			}
			fmt.Printf("ERROR: %s", err)

		// Read from Events.
		case e, ok := <-w.Events:
			if !ok {
				// getting here means w.Close() event has occurred
				abort(1, "Encountered monitoring failure")
			}

			eventOperator := e.Op.String()
			filename := e.Name
			// i++
			// fmt.Printf("%d: ", i)

			switch eventOperator {
			case "CREATE":
				// fmt.Println(eventOperator + " = need to check file or dir " + filename)
				watchProcessUnidentifiedEntity(filename)

			case "WRITE":
				// fmt.Println(eventOperator + " = need to scan file " + filename)
				watchProcessFile(filename)

			case "CHMOD":
				// fmt.Println(eventOperator + " = ignore")

			case "REMOVE":
				// fmt.Println(eventOperator + " = ignore")

			case "RENAME":
				// fmt.Println(eventOperator + " = if dir, assign watch; if file, scan " + filename)
				watchProcessUnidentifiedEntity(filename)

			default:
				abort(1, "Unable to continue monitoring (unknown event "+eventOperator+" - exiting (failsafe)")
			}

		}
	}
}

func watchProcessUnidentifiedEntity(filename string) {
	st, err := os.Stat(filename)
	if err != nil {
		abort(2, "New entry added but unable to stat "+filename)
	} else if st.IsDir() {
		watchProcessDirectory(filename)
	} else {
		watchProcessFile(filename)
	}
}

func watchProcessDirectory(dir string) {
	registerDirectory(dir)
}

func watchProcessFile(filename string) {
	sha_bin, _, _ := getFileSha256(filename)
	if watchedSHAs[sha_bin] {
		fmt.Println("Change: " + filename + " [matched]")
		if cli_check == 0 {
			abort(1, "File on watchlist detected")
		}
		if cli_disclose {
			tsLogger(time.Now().Unix(), false, filename, sha_bin)
		}
		watchedFileDetected = true
	} else {
		fmt.Println("Change: " + filename + " [ok]")
	}
}

// detectTriggered is called when a watched-for file is found (hit) or an internal action fails which compromises security (failsafe).
func detectTriggered(reason string) {
	if cli_check == 0 {
		abort(2, reason)
	}
	watchedFileDetected = true
}

// registerDirectory adds a directory to the watcher, or if unsuccessful declared the detection as triggered (failsafe).
func registerDirectory(dir string) {
	fmt.Println("Registering directory", dir)
	err := watcher.Add(dir)
	if err != nil {
		detectTriggered("Unable to register watcher on " + dir)
	}
}

func healthCheckResponder(w http.ResponseWriter, req *http.Request) {
	if !watchedFileDetected {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("200 - OK\n"))
	} else {
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte("503 - Detected\n"))
	}
}

func healthCheckLogDisplay(w http.ResponseWriter, req *http.Request) {
	if len(watchDetected) == 0 {
		// No logs found
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("404 - Not found\n"))
	} else {
		// Details of logs
		w.WriteHeader(http.StatusOK)

		for _, d := range watchDetected {
			row := fmt.Sprintf("%d,%32x,%t,%s\n", d.timeStamp, d.sha, d.duringPrescan, d.fileName)
			w.Write([]byte(row))
		}
	}
}

func det(args []string) {
	// Process CLI and perform sanity checks
	num, files, found := getSSFs(args)
	slog.Debug("cli handler", "num", num, "files", files, "found", found)
	switch true {
	case num > 20:
		abort(8, "Too many watchlists")
	case num < 1:
		abort(9, "You need to give at least one SSF file to use as the watch list")
	}
	if cli_check != 0 && (cli_check < 80 || cli_check > 65535) {
		abort(1, "Invalid health check value - must be 0 or between 80..65535")
	}

	// Key variables
	watchedFileDetected = false               // watched files - for precheck and monitor phases
	watchedSHAs = make(map[binsha]bool, 1000) // stored binary SHAs

	// Phase 1 - get watch list from cli and ingest as binary
	conditionalMessage(cli_verbose, "Phase 1 - establishing watch list")

	// ingest SHAs
	for i := range num {
		if !found[i] {
			// should be a failsafe *FIXME*
			fmt.Printf("Signature file '%s' not found\n", files[i])
			continue
		}

		conditionalMessage(cli_verbose, "Reading "+files[i]+"...")
		var r *os.File
		r, err := os.Open(files[i])
		if err != nil {
			fmt.Printf("Signature file '%s' cannot be read (check permissions)", files[i])
			continue
		}
		defer r.Close()

		lineno := 0 // local file line number
		scanner := bufio.NewScanner(r)
		for scanner.Scan() {
			// process the line from scanner (from the SSF file)
			s := scanner.Text()
			lineno++

			// drop comments or empty lines or too-short lines
			if len(s) == 0 || s[0:1] == "#" {
				continue
			}
			if len(s) < 43 { // not enough for a Base64 SHA256
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
	conditionalMessage(cli_verbose, fmt.Sprintf("Watch list has %d signature(s)", len(watchedSHAs)))

	// Phase 2 - scan the cwd (or path)
	if !cli_noprecheck {
		conditionalMessage(cli_verbose, "\nPhase 2 - scanning existing file space")
		checkTime := time.Now().Unix()

		// Call the tree walker to generate a file list (as a channel)
		var startpath string = "."
		if cli_path != "" {
			startpath = cli_path // add validation here
		}
		fileQueue := make(chan triplex, 4096)
		go func() {
			defer close(fileQueue)
			walkTreeYieldFilesToChannel(startpath, fileQueue, cli_nodot)
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
				if cli_disclose {
					tsLogger(checkTime, true, filerec.filename, sha_bin)
				}
				if cli_asap {
					break
				}
			}

			total_files++
		}
		if watchedFileDetected && cli_check == 0 {
			abort(1, "One or more watched files found during pre-launch check")
			// triggerDetect()
		}
		fmt.Printf("Scanned %d files - no problems\n", total_files)
	}
	conditionalMessage(cli_verbose && cli_noprecheck, "Skipping phase 2 (pre-check)")

	// Phase 3: watch directories
	conditionalMessage(cli_verbose, "\nPhase 3 - monitoring directories")

	// Create new watcher and assign watchLoop to run it.
	var err error
	watcher, err = fsnotify.NewWatcher()
	if err != nil {
		log.Fatal(err)
	}
	defer watcher.Close() // expect to never trigger
	go watchLoop(watcher)

	// Use tree walker to get all directories, and register them with watcher.
	var startpath string = "."
	if cli_path != "" {
		startpath = cli_path // add validation here
	}
	directoryQueue := make(chan string, 4096)
	go func() {
		defer close(directoryQueue)
		walkTreeYieldDirectoriesToChannel(startpath, directoryQueue, cli_nodot)
	}()
	for dir := range directoryQueue {
		registerDirectory(dir)
	}

	// (Optionally) stand up HTTP health-check server
	if cli_check != 0 {
		servingPort := fmt.Sprintf(":%d", cli_check)
		http.HandleFunc("/", healthCheckResponder)
		if cli_disclose {
			http.HandleFunc("/log", healthCheckLogDisplay)
		}
		go func() {
			http.ListenAndServe(servingPort, nil)
		}()
		conditionalMessage(cli_verbose, "Status indicated by health-check http://localhost"+servingPort+" (not by exit)")
	}

	// Block main goroutine forever.
	fmt.Println("Monitoring... press ^C to exit")
	<-make(chan struct{})
}
