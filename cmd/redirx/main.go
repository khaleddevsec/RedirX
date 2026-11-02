package main

import (
	"fmt"
	"os"

	"redirx/internal/cli"
)

func main() {
	// Normalize common single-dash long flags for CLI compatibility
	for i, arg := range os.Args {
		switch arg {
		case "-stdin":
			os.Args[i] = "--stdin"
		case "-silent":
			os.Args[i] = "--silent"
		case "-name":
			os.Args[i] = "--name"
		case "-format":
			os.Args[i] = "--format"
		case "-output":
			os.Args[i] = "--output"
		case "-version":
			os.Args[i] = "--version"
		case "-update":
			os.Args[i] = "--update"
		}
	}

	cmd := cli.NewRootCmd()
	if err := cmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

