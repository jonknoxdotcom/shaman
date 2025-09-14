/*
Copyright © 2025 Jon Knox <jon@k2x.io>
*/
package cmd

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"

	"github.com/spf13/cobra"
)

// anonymiseCmd represents the anonymise command
var test3Cmd = &cobra.Command{
	Use:   "test3",
	Short: "This is used to test different file-system and SSF access interfaces",
	Long: `This is used to test different file-system and SSF access interfaces.
Not intended for functional use.`,
	Aliases: []string{"test3", "t3"},
	Run: func(cmd *cobra.Command, args []string) {
		t3(args)
	},
}

func init() {
	rootCmd.AddCommand(test3Cmd)

	test3Cmd.Flags().StringVarP(&cli_path, "path", "p", "", "Path to directory to scan (default is current directory)")
	test3Cmd.Flags().BoolVarP(&cli_nodot, "no-dot", "", false, "Do not include files/directories beginning '.'")
}

// ----------------------- Test3 function below this line -----------------------

func t3(args []string) {
	var f *os.File
	var err error
	var s string

	fmt.Println("\nTEST3")
	fmt.Println("number of cpus is", runtime.NumCPU())

	fmt.Println("cli")
	_, files, _ := getSSFs(args)
	fnr := files[0]
	fmt.Println("fnr=" + fnr)

	fmt.Println("open")
	f, err = os.Open(fnr)
	conditionalAbort(err != nil, 1, "Unable to open file "+fnr)
	// f.Close()

	var r *bufio.Reader
	r = bufio.NewReaderSize(f, 4096)
	// b4, err := r.Peek(5)
	// fmt.Printf("5 bytes: %s\n", string(b4))

	for true {
		fmt.Print("b=", r.Buffered()) // amount left
		s, err = r.ReadString('\n')
		s = strings.TrimRight(s, "\n")
		fmt.Println(" : '" + s + "'")

		if err == nil {
			continue
		} else if err == io.EOF {
			break
		} else {
			fmt.Print("Unexpected error ")
			fmt.Println(err)
			break
		}

	}

	fmt.Println("reset")
	f.Seek(0, io.SeekStart)
	r.Reset(f)

	s, err = r.ReadString('\n')
	fmt.Println(s)

	// fmt.Println("scan")
	// scan := new(readSSF)
	// if scan.open(fnr) != nil {
	// 	abort(4, "internal error unable to start seeking on file read handle")
	// }
	// defer scan.close()

	os.Exit(0) //explicit (because we're an rc=0 or rc=1 depending on whether any changes)
}
