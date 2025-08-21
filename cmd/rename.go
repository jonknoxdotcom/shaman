/*
Copyright © 2025 Jon Knox <jon@k2x.io>
*/
package cmd

import (
	"fmt"
	"image"
	_ "image/jpeg"
	_ "image/png"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/image/webp"
)

// -------------------------------- Cobra management -------------------------------

// generateCmd represents the generate command
var renameCmd = &cobra.Command{
	Use:   "rename",
	Short: "Rename the files in the cwd with bash",
	Long: `shaman rename
Reads the current tree, and puts into a bash script (stdout) that you can easily edit`,
	Aliases: []string{"ren"},
	GroupID: "G3",

	Args: cobra.MaximumNArgs(0),
	Run: func(cmd *cobra.Command, args []string) {
		ren(args)
	},
}

func init() {
	rootCmd.AddCommand(renameCmd)

	renameCmd.Flags().BoolVarP(&cli_cwd, "cwd", "", false, "Current working directory only (no subdirectories)")
	renameCmd.Flags().BoolVarP(&cli_flatten, "flatten", "", false, "Flatten all files to single directory")
	renameCmd.Flags().BoolVarP(&cli_refile, "refile", "", false, "Re-file single files into folders")
	renameCmd.Flags().BoolVarP(&cli_pixels, "pixels", "", false, "Append jpg/png/webp image filenames with pixel size")
	renameCmd.Flags().BoolVarP(&cli_nodot, "no-dot", "", false, "Do not include any dot directories / mac resource forks")
}

// ----------------------- Rename function below this line -----------------------

func decodePNG(fn string) (error, int, int) {
	if reader, err := os.Open(fn); err == nil {
		defer reader.Close()

		im, _, err := image.DecodeConfig(reader) // fast determination of colour depth and size without decoding whole image
		if err != nil {
			return err, 0, 0
		}
		// fmt.Printf("%s %d %d\n", fn, im.Width, im.Height, im.ColorModel)
		return nil, im.Width, im.Height
	}
	return nil, 0, 0
}

func decodeJPEG(fn string) (error, int, int) {
	if reader, err := os.Open(fn); err == nil {
		defer reader.Close()

		im, _, err := image.DecodeConfig(reader) // fast determination of colour depth and size without decoding whole image
		if err != nil {
			return err, 0, 0
		}
		// fmt.Printf("%s %d %d\n", fn, im.Width, im.Height)
		return nil, im.Width, im.Height
	}
	return nil, 0, 0
}

func decodeWEBP(fn string) (error, int, int) {
	if reader, err := os.Open(fn); err == nil {
		defer reader.Close()

		im, err := webp.DecodeConfig(reader) // fast determination of colour depth and size without decoding whole image
		if err != nil {
			return err, 0, 0
		}
		// fmt.Printf("%s %d %d\n", fn, im.Width, im.Height)
		return nil, im.Width, im.Height
	}
	return nil, 0, 0
}

func ren(args []string) {
	num, _, _ := getSSFs(args)
	if num > 0 {
		abort(8, "Too many .ssf files specified)")
	}

	// ------------------------------------------

	// find count and longest filename

	var startpath string = "."
	if cli_path != "" {
		startpath = cli_path // add validation here
	}
	fileQueue := make(chan triplex, 4096)
	go func() {
		defer close(fileQueue)
		walkTreeYieldFilesToChannel(startpath, fileQueue, cli_nodot)
	}()

	// count and compute length of longest line
	var numFiles int
	var longest int
	var fn string
	for filerec := range fileQueue {
		fn = filerec.filename
		// reject - no dot
		if cli_nodot && (fn[0:1] == "." || strings.Index(fn, "/.") > 0) {
			continue
		}
		// reject - cwd only
		if cli_cwd && strings.Index(fn, "/") > 0 {
			continue
		}

		numFiles++
		fn = "\"" + strings.Replace(fn, "\"", "\\\"", -1) + "\""
		if len(fn) > longest {
			longest = len(fn)
		}
	}
	if numFiles == 0 {
		abort(1, "No files found")
	}

	// ------------------------------------------

	// call the tree walker to generate a file list (as a channel)
	fileQueue = make(chan triplex, 4096)
	go func() {
		defer close(fileQueue)
		walkTreeYieldFilesToChannel(startpath, fileQueue, cli_nodot)
	}()

	// create move list *FIXME* needs pre-sizing
	var folder string
	var lastfolder string
	for filerec := range fileQueue {
		fn = filerec.filename

		// no dot
		if cli_nodot && (fn[0:1] == "." || strings.Index(fn, "/.") > 0) {
			continue
		}

		// cwd only
		if cli_cwd && strings.Index(fn, "/") > 0 {
			continue
		}
		// fmt.Println(fn)

		source := "\"" + strings.Replace(fn, "\"", "\\\"", -1) + "\""
		dest := source
		if cli_flatten {
			// completely flatten
			dest = strings.Replace(dest, "/", "--", -1)
		}
		if cli_refile {
			// only expand 1-deep tree
			dest = strings.Replace(dest, "--", "/", 1)
			pos := strings.Index(dest, "/")
			if pos != -1 {
				folder = dest[1:pos]
			}
		}
		if cli_pixels {
			lastDot := strings.LastIndex(dest, ".")
			if lastDot > 0 {
				var x int = 0
				var y int = 0

				ending := dest[lastDot:]

				suffix := ""
				if ending == ".png\"" || ending == ".PNG\"" {
					_, x, y = decodePNG(fn)
				}

				if ending == ".jpeg\"" || ending == ".jpg\"" || ending == ".JPEG\"" || ending == ".JPG\"" {
					_, x, y = decodeJPEG(fn)
				}

				if ending == ".webp\"" || ending == ".WEBP\"" {
					_, x, y = decodeWEBP(fn)
				}

				if x != 0 && y != 0 {
					suffix = fmt.Sprintf("-%dx%d", x, y)
					dest = dest[0:len(dest)-len(ending)] + suffix + ending
				}
			}
		}

		if folder != lastfolder {
			fmt.Printf("mkdir \"%s\"\n", folder)
			lastfolder = folder
		}
		source = source + strings.Repeat(" ", longest-len(source)+2)
		fmt.Printf("mv %s%s\n", source, dest)
	}

}
