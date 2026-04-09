package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/tuntufye/deadcheck/internal/model"
)

var version = "v0.1.0"

const (
	exitOK        = 0
	exitThreshold = 1
	exitUsage     = 2
	exitStartup   = 3
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	flags := flag.NewFlagSet("deadcheck", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)

	var (
		jsonOut     bool
		verbose     bool
		minSeverity string
		failBelow   int
		pathFlag    string
		workers     int
		timeout     time.Duration
		showVersion bool
	)

	flags.BoolVar(&jsonOut, "json", false, "emit JSON output")
	flags.BoolVar(&verbose, "verbose", false, "show info findings in terminal output")
	flags.StringVar(&minSeverity, "min-severity", string(model.SeverityWarning), "minimum severity: info, warning, critical")
	flags.IntVar(&failBelow, "fail-below", 0, "exit 1 if score is below threshold")
	flags.StringVar(&pathFlag, "path", "", "target directory to scan")
	flags.IntVar(&workers, "workers", 10, "maximum concurrent dependency checks")
	flags.DurationVar(&timeout, "timeout", 30*time.Second, "scan timeout")
	flags.BoolVar(&showVersion, "version", false, "print version")

	if err := flags.Parse(args); err != nil {
		return fatal(jsonOut, exitUsage, err.Error())
	}

	if showVersion {
		fmt.Fprintln(os.Stdout, version)
		return exitOK
	}

	target, err := resolveTarget(pathFlag, flags.Args())
	if err != nil {
		return fatal(jsonOut, exitUsage, err.Error())
	}

	sev, ok := model.ParseSeverity(minSeverity)
	if verbose {
		sev = model.SeverityInfo
		ok = true
	}
	if !ok {
		return fatal(jsonOut, exitUsage, "invalid --min-severity; expected info, warning, or critical")
	}

	if workers <= 0 {
		return fatal(jsonOut, exitUsage, "--workers must be greater than 0")
	}
	if timeout <= 0 {
		return fatal(jsonOut, exitUsage, "--timeout must be greater than 0")
	}

	cfg := Config{
		Path:        target,
		MinSeverity: sev,
		Workers:     workers,
		Timeout:     timeout,
		JSON:        jsonOut,
		FailBelow:   failBelow,
		Version:     version,
	}

	if err := execute(context.Background(), cfg); err != nil {
		var exitErr *ExitError
		if errors.As(err, &exitErr) {
			if exitErr.Message == "" {
				return exitErr.Code
			}
			return fatal(jsonOut, exitErr.Code, exitErr.Message)
		}
		return fatal(jsonOut, exitStartup, err.Error())
	}
	return exitOK
}

func resolveTarget(pathFlag string, positional []string) (string, error) {
	switch {
	case len(positional) > 1:
		return "", fmt.Errorf("expected at most one positional path")
	case pathFlag != "" && len(positional) == 1 && pathFlag != positional[0]:
		return "", fmt.Errorf("positional path and --path must match when both are provided")
	case pathFlag != "":
		return pathFlag, nil
	case len(positional) == 1:
		return positional[0], nil
	default:
		return ".", nil
	}
}

func fatal(jsonOut bool, code int, message string) int {
	if jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(model.FatalResult{Error: message, Code: code})
	} else {
		fmt.Fprintln(os.Stderr, "deadcheck:", message)
	}
	return code
}
