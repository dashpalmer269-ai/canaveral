// Command canaveral is the entry point for the Canaveral forensic triage tool.
package main

import (
	"flag"
	"fmt"
	"os"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "0.0.0-dev"

func main() {
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println(version)
		return
	}

	fmt.Fprintf(os.Stderr, "Canaveral %s: pre-implementation build (milestone M0 skeleton).\n", version)
	fmt.Fprintln(os.Stderr, "No collectors are implemented. Nothing was inspected and no report was produced.")
	os.Exit(2)
}
