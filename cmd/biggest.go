/*
Copyright © 2025 Jon Knox <jon@k2x.io>
*/
package cmd

import (
	"bufio"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
)

// biggestCmd represents the biggest command
var biggestCmd = &cobra.Command{
	Use:     "biggest",
	Short:   "Show the names of the largest files",
	Long:    `Finds the top-10 largest files in an .ssf file`,
	Aliases: []string{"big", "largest", "lar"},
	Args:    cobra.MaximumNArgs(10), // handle in code
	GroupID: "G2",

	Run: func(cmd *cobra.Command, args []string) {
		big(args)
	},
}

var cli_count uint = 10

func init() {
	rootCmd.AddCommand(biggestCmd)

	biggestCmd.Flags().UintVarP(&cli_count, "count", "c", 10, "Specify number of files to show (default: 10)")

}

// ----------------------- "Biggest" (largest) function below this line -----------------------

func big(args []string) {
	// fmt.Println("'" + intAsStringWithCommas(123) + "'")
	// fmt.Println("'" + intAsStringWithCommas(1234) + "'")
	// fmt.Println("'" + intAsStringWithCommas(12345) + "'")
	// fmt.Println("'" + intAsStringWithCommas(123456) + "'")
	// fmt.Println("'" + intAsStringWithCommas(1234567) + "'")
	// fmt.Println("'" + intAsStringWithCommas(12345678) + "'")
	// fmt.Println("'" + intAsStringWithCommas(123456789) + "'")
	// fmt.Println("'" + intAsStringWithCommas(1234567890) + "'")
	// fmt.Println("'" + intAsStringWithCommas(12345678901) + "'")
	// fmt.Println("'" + intAsStringWithCommas(123456789012) + "'")

	// Make sure we have a single input file that exists / error appropriately
	num, files, found := getSSFs(args)
	slog.Debug("cli handler", "num", num, "files", files, "found", found)
	switch true {
	case num > 8:
		abort(8, "Too many .ssf files specified - eight is enough")
	case num < 1:
		abort(9, "Need an SSF file to perform largest file check")
	case !found[0]:
		abort(6, "Input SSF file '"+files[0]+"' does not exist")
	}

	fn := files[0]

	// We get the top 20
	N := 50
	sizes := make([]string, N)
	ident := make([]string, N)
	names := make([]string, N)
	dupes := make([]int, N)

	for x := 0; x < N; x++ {
		// fmt.Print(x, " ")
		sizes[x] = "00000000"
		names[x] = "(no entry)"
		ident[x] = ""
		dupes[x] = 0
	}

	var r *os.File
	r, err := os.Open(fn)
	if err != nil {
		abort(4, "Can't open "+fn+" - stuck!")
	}
	defer r.Close()

	var s string
	var thresh string = "00000000"
	var lineno int
	scanner := bufio.NewScanner(r)

SCANLOOP:
	for scanner.Scan() {
		s = scanner.Text()
		lineno++
		if len(s) == 0 || s[0:1] == "#" {
			// drop comments or empty lines
			continue
		}

		// check size with least kerfuffle
		pos1 := strings.Index(s, " ")
		if pos1 == -1 || pos1 < 55 {
			fmt.Printf("Skipping line %d - Invalid format (pos %d)\n", lineno, pos1)
			continue
		}
		temp := "000000" + s[51:pos1]
		size := temp[len(temp)-10:]
		if size < thresh {
			// off the bottom - no need to do any more
			// fmt.Println("off the bottom")
			continue
		}

		// get rest of fields
		id := s[0:pos1]
		pos2 := strings.Index(s, " :")
		name := s[pos2+2:]
		// fmt.Printf("\nID='%s', Name='%s', size8='%s'\n", id, name, size)
		// id = s[0:pos]
		// shab64 = s[0:43]
		// modtime = s[43:51]
		// length = s[51:pos]
		// name = s[pos+2:]
		// return id, shab64, modtime, len

		// quickly check for duplication
		for x := 0; x < N; x++ {
			if ident[x] == id {
				dupes[x]++
				continue SCANLOOP
			}
		}

		// perform ascending insertion
		// fmt.Println("Want to insert", size, "into", sizes)
		pos := N - 2
		for pos >= 0 {
			// fmt.Print("CHK", size, "<", sizes[pos], " (pos=", pos, ")\n")

			if size < sizes[pos] {
				// fmt.Print("\n", "BREAK: ", size, "<", sizes[pos], " pos=", pos, "\n")
				break
			}

			// shift content down
			// fmt.Print("/ roll ", pos, "to", pos+1)
			sizes[pos+1] = sizes[pos]
			names[pos+1] = names[pos]
			ident[pos+1] = ident[pos]
			dupes[pos+1] = dupes[pos]
			pos--
		}

		// record insertion
		pos++
		// fmt.Printf("Insert %s at %d\n", size, pos)

		sizes[pos] = size
		names[pos] = name
		ident[pos] = id
		dupes[pos] = 1
		thresh = sizes[N-1]
	}

	fmt.Println("TOP", N, "BY SIZE")
	fmt.Println("POS   HEX SIZE   -----SIZE-----   #  FILENAME")
	var decnum int64 = 0
	for x := 0; x < N; x++ {
		decnum, _ = strconv.ParseInt(sizes[x], 16, 0)
		//fmt.Printf("%2d:  %s%12d %3d  %s\n", x+1, sizes[x], decnum, dupes[x], names[x])
		fmt.Printf("%2d:  %s%16s %3d  %s\n", x+1, sizes[x], intAsStringWithCommas(decnum), dupes[x], names[x])
	}
}
