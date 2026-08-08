// Command configdump reads a Junos configuration and prints the parsed
// model as JSON. A development tool for the parity checklist (task 09):
// it lets you diff the Go output side by side with the Python output on
// the same fixtures. Not embedded in the production image.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/local/srxtool-go/internal/config"
)

func main() {
	allowEmpty := flag.Bool("allow-empty", false, "don't fail on an empty model")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: configdump [-allow-empty] <conf-file>\n")
		flag.PrintDefaults()
	}
	flag.Parse()
	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(2)
	}

	data, err := os.ReadFile(flag.Arg(0))
	if err != nil {
		fmt.Fprintln(os.Stderr, "unable to read")
		os.Exit(1)
	}

	m, err := config.Parse(data, config.Options{AllowEmpty: *allowEmpty})
	if err != nil {
		var fe *config.FormatError
		switch {
		case errors.As(err, &fe):
			fmt.Fprintf(os.Stderr, "format error: %s\n", fe)
		case errors.Is(err, config.ErrTooLarge):
			fmt.Fprintln(os.Stderr, "file too large")
		default:
			fmt.Fprintln(os.Stderr, "parsing error")
		}
		os.Exit(1)
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(m); err != nil {
		fmt.Fprintln(os.Stderr, "unable to encode JSON")
		os.Exit(1)
	}
}
