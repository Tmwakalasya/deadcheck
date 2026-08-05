package main

import (
	"os"

	"github.com/Tmwakalasya/deadcheck/internal/cli"
)

var version = "v0.2.0-dev"

func main() {
	os.Exit(cli.Main(os.Args[1:], version, os.Stdin, os.Stdout, os.Stderr))
}
