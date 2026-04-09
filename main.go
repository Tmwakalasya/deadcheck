package main

import (
	"os"

	"github.com/Tmwakalasya/deadcheck/internal/cli"
)

var version = "v0.1.0"

func main() {
	os.Exit(cli.Main(os.Args[1:], version, os.Stdout, os.Stderr))
}
