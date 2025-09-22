/*
Copyright © 2025 Jon Knox <jon@k2x.io>
*/
package cmd

import (
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"bufio"
	"fmt"
)

// -------------------------------- Cobra management -------------------------------

// generateCmd represents the generate command
var generateCmd = &cobra.Command{
	Use:   "generate [file.ssf]",
	Short: "Generate a sha-manager signature format (.ssf) file",
	Long: `shaman generate
Generate a sha-manager format (.ssf) file from specified directory (or current directory if none specified), 
writing the output to a named file (or stdout if none given)`,
	Aliases: []string{"gen"},
	Args:    cobra.MaximumNArgs(1),
	GroupID: "G1",
	Run: func(cmd *cobra.Command, args []string) {
		gen(args)
	},
}

func init() {
	rootCmd.AddCommand(generateCmd)

	generateCmd.Flags().StringVarP(&cli_path, "path", "p", "", "Path to directory to scan (default is current directory)")
	generateCmd.Flags().IntVarP(&cli_format, "format", "f", 0, "Format/anonymisation level (1..5 or 9")
	generateCmd.Flags().BoolVarP(&cli_dupes, "dupes", "d", false, "Whether to show dupes (as comments) on completion")
	generateCmd.Flags().BoolVarP(&cli_grand, "grand-totals", "g", false, "Display grand totals of bytes/files on completion")
	generateCmd.Flags().BoolVarP(&cli_verbose, "verbose", "v", false, "Give running commentary of update")
	generateCmd.Flags().BoolVarP(&cli_nodot, "no-dot", "", false, "Do not include files/directories beginning '.'")
	generateCmd.Flags().BoolVarP(&cli_eta, "eta", "", false, "Give completion estimate after 30s of processing")
}

// ----------------------- Generate function below this line -----------------------

// Rate: 167 files per sec (10k/min) for Desktop on MBP A2141

func genForecasttoStdErr(wt *walkTree, prefix string) (int64, int64) {
	fmt.Print(prefix)
	tempf, tempb, tempr, _ := wt.psize()
	fmt.Printf("%s files / %s bytes (at %s fps)\n",
		intAsStringWithCommas(tempf),
		intAsStringWithCommas(tempb),
		intAsStringWithCommas(tempr))
	return tempf, tempb
}

func genETAtoStdErr(wt *walkTree, prefix string) {
	//make call to walker for ETA here
	nf, nb, nfa, nba, t, err := wt.getProgress()
	//_, _, _, _, secs, err := wt.getProgress()
	if err == nil {
		var secsElapsed, bytesPerSec, secsRemaining, fPercent, bPercent float32
		secsElapsed = float32(t) / 1000.0
		bytesPerSec = float32(nb) / secsElapsed
		secsRemaining = float32(nba-nb) / bytesPerSec
		fPercent = 100 * float32(nf) / float32(nfa)
		bPercent = 100 * float32(nb) / float32(nba)
		totalTime := secsElapsed + secsRemaining
		totalUnit := "s"
		if totalTime > 60 {
			totalTime = totalTime / 60
			totalUnit = "m"

			if totalTime > 60 {
				totalTime = totalTime / 60
				totalUnit = "h"
			}
		}
		fmt.Printf("%s done=%0.1fs, remain=%0.1fs, total=%0.1f (%0.1f%s) \n", prefix, secsElapsed, secsRemaining, secsElapsed+secsRemaining, totalTime, totalUnit)
		fmt.Printf("  Files:  %5.1f%%  %d / %d\n", fPercent, nf, nfa)
		fmt.Printf("  Bytes:  %5.1f%%  %d / %d\n", bPercent, nb, nba)
	}
}

func genWorkDone(wt *walkTree, prefix string) {
	// this should return all work done
	nf, nb, nfa, nba, t, err := wt.getProgress()
	if err == nil {
		var secsElapsed, fPercent, bPercent float32
		secsElapsed = float32(t) / 1000.0
		//bytesPerSec = float32(nb) / secsElapsed
		fPercent = 100 * float32(nf) / float32(nfa)
		bPercent = 100 * float32(nb) / float32(nba)

		if nba != nb {
			fmt.Printf("%s actual=%f0.1s (partial)\n", prefix, secsElapsed)
			fmt.Printf("  Files:  %5.1f%%  %d / %d\n", fPercent, nf, nfa)
			fmt.Printf("  Bytes:  %5.1f%%  %d / %d\n", bPercent, nb, nba)
		} else {
			totalTime := secsElapsed
			totalUnit := "s"
			if totalTime > 60 {
				totalTime = totalTime / 60
				totalUnit = "m"

				if totalTime > 60 {
					totalTime = totalTime / 60
					totalUnit = "h"
				}
			}
			fmt.Printf("%s actual=%0.1fs (%0.1f%s) \n", prefix, secsElapsed, totalTime, totalUnit)
		}
	}
}

func gen(args []string) {
	var w *bufio.Writer
	var fn string = "" // Output file (for "" for stdout)
	var ticker bool = true
	var form int = 5      // format defaults to 5
	var total_files int64 // files processed
	var total_bytes int64 // bytes processed

	// for update, the format default is 5 (full)
	if cli_format != 0 {
		form = cli_format
	}
	// process CLI
	num, files, found := getSSFs(args)
	slog.Debug("cli handler", "num", num, "files", files, "found", found)
	switch true {
	case num == 0:
		// direct to stdout - switch off all updates
		ticker = false // no dots if writing to stdout
		cli_verbose = false
	case num > 2:
		abort(8, "Too many .ssf files specified)")
	case num == 1 && !found[0]:
		fn = files[0]
		ticker = false
	case num == 1 && found[0]:
		abort(6, "Output file '"+files[0]+"' already exists")
	}

	// find ends .ssf??

	// open writer (stdout or file)
	w = writeInit(fn)

	// Call the tree walker to generate a file list (as a channel)
	var startpath string = "."
	if cli_path != "" {
		startpath = cli_path // add validation here
	}

	var tempb, tempf int64
	wt := new(walkTree)
	wt.path(startpath, cli_nodot)
	// tempf, tempb, _ := wt.psize()
	if cli_eta {
		tempf, tempb = genForecasttoStdErr(wt, "Work to do:   ")
	}
	// fmt.Println("Est:", tempf, "files", tempb, "bytes")

	fileQueue := make(chan triplex, 4096)
	go func() {
		defer close(fileQueue)
		walkTreeYieldFilesToChannel(startpath, fileQueue, cli_nodot)
	}()

	var verbosity int = 1
	if cli_verbose {
		fmt.Println("Generating:")
		verbosity = 2
		ticker = false
	} else {
		if num == 1 {
			fmt.Print("Processing")
			ticker = true
		}
	}

	// interruption handler - ^C and kill controlled exits
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		if cli_eta {
			genETAtoStdErr(wt, "\nWork at stop: ")
		}

		// cleanup()
		w.Flush()
		if cli_eta {
			if fn == "" {
				fmt.Printf("\nSTOPPED - at %d%% data digested - %s of %s records generated\n",
					int64(100*total_bytes/tempb),
					intAsStringWithCommas(total_files),
					intAsStringWithCommas(tempf))
			} else {
				fmt.Printf("\nSTOPPED - at %d%% data digested - %s of %s records written\n",
					int64(100*total_bytes/tempb),
					intAsStringWithCommas(total_files),
					intAsStringWithCommas(tempf))
			}
		} else {
			// no ETA
			if fn == "" {
				fmt.Printf("\nSTOPPED - %s records generated\n",
					intAsStringWithCommas(total_files))
			} else {
				fmt.Printf("\nSTOPPED - %s records written\n",
					intAsStringWithCommas(total_files))
			}

		}
		if fn != "" {
			fmt.Printf("To resume, use:\n    shaman update \"%s\" --overwrite\n", fn)
		}
		os.Exit(1)
	}()

	// ETA handler - for >30s runs, give a completion time
	var timerETA *time.Timer
	if cli_eta && verbosity < 2 {
		timerETA = time.NewTimer(time.Second * 45)
		go func() {
			<-timerETA.C
			fmt.Println()
			genETAtoStdErr(wt, "Work so far:  ")
			//fmt.Println(wt)
			fmt.Print("Continuing")
		}()
		// stop2 := timerETA.Stop()
		// if stop2 {
		// 	fmt.Println("Timer 2 stopped")
		// }

	}

	// process file list to generate SSF records
	for filerec := range fileQueue {
		// drop if files or directories begins "." and nodot asserted
		// if cli_nodot && (strings.Contains(filerec.filename, "/.") || filerec.filename[0:1] == ".") {
		// 	continue
		// }

		_, sha_b64, _ := getFileSha256(filerec.filename)

		modt := fmt.Sprintf("%8x", filerec.modified)
		size := fmt.Sprintf("%04x", filerec.size)
		writeRecord(w, true, form, verbosity, "N", sha_b64, modt, size, filerec.filename, "")

		// stats and ticks (dot every 100, flush every 500)
		total_bytes += filerec.size
		total_files++
		wt.setProgress(total_files, total_bytes)

		if ticker && total_files%100 == 0 {
			fmt.Print(".")
		}
	}
	w.Flush()

	if ticker {
		fmt.Println(".")
	}
	if cli_verbose {
		fmt.Printf("Total: %s files, %s bytes\n", intAsStringWithCommas(total_files), intAsStringWithCommas(total_bytes))
	}
	if cli_eta {
		genWorkDone(wt, "Work at end:  ")
	}

}
