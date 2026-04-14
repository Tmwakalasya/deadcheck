package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/Tmwakalasya/deadcheck/internal/model"
	"github.com/Tmwakalasya/deadcheck/internal/registry"
	"github.com/Tmwakalasya/deadcheck/internal/report"
	"github.com/Tmwakalasya/deadcheck/internal/scanner"
)

const (
	exitOK        = 0
	exitThreshold = 1
	exitUsage     = 2
	exitStartup   = 3
)

type Config struct {
	Path           string
	MinSeverity    model.Severity
	Workers        int
	Timeout        time.Duration
	JSON           bool
	ProductionOnly bool
	FailBelow      int
	Version        string
}

type ExitError struct {
	Code    int
	Message string
}

func (e *ExitError) Error() string {
	return e.Message
}

func Main(args []string, version string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("deadcheck", flag.ContinueOnError)
	flags.SetOutput(stderr)

	var (
		jsonOut        bool
		productionOnly bool
		verbose        bool
		minSeverity    string
		failBelow      int
		pathFlag       string
		workers        int
		timeout        time.Duration
		showVersion    bool
	)

	flags.BoolVar(&jsonOut, "json", false, "emit JSON output")
	flags.BoolVar(&productionOnly, "production-only", false, "exclude devDependencies from scans and scoring")
	flags.BoolVar(&verbose, "verbose", false, "show info findings in terminal output")
	flags.StringVar(&minSeverity, "min-severity", string(model.SeverityWarning), "minimum severity: info, warning, critical")
	flags.IntVar(&failBelow, "fail-below", 0, "exit 1 if score is below threshold")
	flags.StringVar(&pathFlag, "path", "", "target directory to scan")
	flags.IntVar(&workers, "workers", 10, "maximum concurrent dependency checks")
	flags.DurationVar(&timeout, "timeout", 30*time.Second, "scan timeout")
	flags.BoolVar(&showVersion, "version", false, "print version")

	if err := flags.Parse(args); err != nil {
		return fatal(stdout, stderr, jsonOut, exitUsage, err.Error())
	}

	if showVersion {
		_, _ = fmt.Fprintln(stdout, version)
		return exitOK
	}

	target, err := resolveTarget(pathFlag, flags.Args())
	if err != nil {
		return fatal(stdout, stderr, jsonOut, exitUsage, err.Error())
	}

	sev, ok := model.ParseSeverity(minSeverity)
	if verbose {
		sev = model.SeverityInfo
		ok = true
	}
	if !ok {
		return fatal(stdout, stderr, jsonOut, exitUsage, "invalid --min-severity; expected info, warning, or critical")
	}

	if workers <= 0 {
		return fatal(stdout, stderr, jsonOut, exitUsage, "--workers must be greater than 0")
	}
	if timeout <= 0 {
		return fatal(stdout, stderr, jsonOut, exitUsage, "--timeout must be greater than 0")
	}

	cfg := Config{
		Path:           target,
		MinSeverity:    sev,
		Workers:        workers,
		Timeout:        timeout,
		JSON:           jsonOut,
		ProductionOnly: productionOnly,
		FailBelow:      failBelow,
		Version:        version,
	}

	if err := execute(context.Background(), cfg, stdout, stderr); err != nil {
		var exitErr *ExitError
		if errors.As(err, &exitErr) {
			if exitErr.Message == "" {
				return exitErr.Code
			}
			return fatal(stdout, stderr, jsonOut, exitErr.Code, exitErr.Message)
		}
		return fatal(stdout, stderr, jsonOut, exitStartup, err.Error())
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

func fatal(stdout, stderr io.Writer, jsonOut bool, code int, message string) int {
	if jsonOut {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(model.FatalResult{Error: message, Code: code})
	} else {
		_, _ = fmt.Fprintln(stderr, "deadcheck:", message)
	}
	return code
}

func execute(ctx context.Context, cfg Config, stdout, stderr io.Writer) error {
	ctx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()

	httpClient := &http.Client{
		Transport: &http.Transport{
			DialContext: (&net.Dialer{
				Timeout: 5 * time.Second,
			}).DialContext,
			ResponseHeaderTimeout: 10 * time.Second,
		},
	}

	scan := scanner.New(httpClient, registry.URLsFromEnv(), scanner.Options{
		Workers:        cfg.Workers,
		ProductionOnly: cfg.ProductionOnly,
	})
	result, err := scan.Scan(ctx, cfg.Path)
	if err != nil {
		if errors.Is(err, scanner.ErrNoSupportedManifest) {
			return &ExitError{Code: exitStartup, Message: err.Error()}
		}
		return err
	}

	if cfg.JSON {
		if err := report.WriteJSON(stdout, result); err != nil {
			return err
		}
	} else {
		if err := report.WriteTable(stdout, stderr, result, report.TableOptions{
			Version:     cfg.Version,
			MinSeverity: cfg.MinSeverity,
			Colorize:    report.ColorEnabled(),
		}); err != nil {
			return err
		}
	}

	if cfg.FailBelow > 0 && result.Score < cfg.FailBelow {
		return &ExitError{Code: exitThreshold}
	}
	return nil
}
