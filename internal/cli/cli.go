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
	"strings"
	"time"

	"github.com/Tmwakalasya/deadcheck/internal/ci"
	"github.com/Tmwakalasya/deadcheck/internal/graph"
	"github.com/Tmwakalasya/deadcheck/internal/model"
	"github.com/Tmwakalasya/deadcheck/internal/registry"
	"github.com/Tmwakalasya/deadcheck/internal/report"
	"github.com/Tmwakalasya/deadcheck/internal/scanner"
	"github.com/Tmwakalasya/deadcheck/internal/tui"
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
	GitHubSummary  bool
	NoTUI          bool
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

func Main(args []string, version string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) > 0 && args[0] == "init" {
		return initMain(args[1:], stdout, stderr)
	}
	if len(args) > 0 && args[0] == "graph" {
		return graphMain(args[1:], version, stdout, stderr)
	}
	if len(args) > 0 && args[0] == "why" {
		return whyMain(args[1:], version, stdout, stderr)
	}

	flags := flag.NewFlagSet("deadcheck", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.Usage = func() {
		_, _ = fmt.Fprintln(stderr, "Usage:")
		_, _ = fmt.Fprintln(stderr, "  deadcheck [flags] [path]")
		_, _ = fmt.Fprintln(stderr, "  deadcheck graph [flags] [path]")
		_, _ = fmt.Fprintln(stderr, "  deadcheck why [flags] <dependency> [path]")
		_, _ = fmt.Fprintln(stderr, "  deadcheck init ci [flags] [path]")
		_, _ = fmt.Fprintln(stderr, "\nScan flags:")
		flags.PrintDefaults()
	}

	var (
		jsonOut        bool
		githubSummary  bool
		noTUI          bool
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
	flags.BoolVar(&githubSummary, "github-summary", false, "write a Markdown report to $GITHUB_STEP_SUMMARY")
	flags.BoolVar(&noTUI, "no-tui", false, "use the non-interactive terminal report")
	flags.BoolVar(&productionOnly, "production-only", false, "exclude devDependencies from scans and scoring")
	flags.BoolVar(&verbose, "verbose", false, "show info findings in terminal output")
	flags.StringVar(&minSeverity, "min-severity", string(model.SeverityWarning), "minimum severity: info, warning, critical")
	flags.IntVar(&failBelow, "fail-below", 0, "exit 1 if score is below threshold")
	flags.StringVar(&pathFlag, "path", "", "target directory to scan")
	flags.IntVar(&workers, "workers", 10, "maximum concurrent dependency checks")
	flags.DurationVar(&timeout, "timeout", 30*time.Second, "scan timeout")
	flags.BoolVar(&showVersion, "version", false, "print version")

	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
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
		GitHubSummary:  githubSummary,
		NoTUI:          noTUI,
		ProductionOnly: productionOnly,
		FailBelow:      failBelow,
		Version:        version,
	}

	if err := execute(context.Background(), cfg, stdin, stdout, stderr); err != nil {
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

func graphMain(args []string, version string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("deadcheck graph", flag.ContinueOnError)
	flags.SetOutput(stderr)

	var (
		jsonOut        bool
		productionOnly bool
		pathFlag       string
		depth          int
		timeout        time.Duration
	)

	flags.BoolVar(&jsonOut, "json", false, "emit the full graph as JSON")
	flags.BoolVar(&productionOnly, "production-only", false, "exclude npm devDependencies from the graph")
	flags.StringVar(&pathFlag, "path", "", "target directory to inspect")
	flags.IntVar(&depth, "depth", 3, "maximum terminal tree depth; 0 shows the full graph")
	flags.DurationVar(&timeout, "timeout", 30*time.Second, "graph resolution timeout")

	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return fatal(stdout, stderr, jsonOut, exitUsage, err.Error())
	}
	target, err := resolveTarget(pathFlag, flags.Args())
	if err != nil {
		return fatal(stdout, stderr, jsonOut, exitUsage, err.Error())
	}
	if depth < 0 {
		return fatal(stdout, stderr, jsonOut, exitUsage, "--depth must be 0 or greater")
	}
	if timeout <= 0 {
		return fatal(stdout, stderr, jsonOut, exitUsage, "--timeout must be greater than 0")
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	result, err := graph.New().Build(ctx, target, graph.Options{ProductionOnly: productionOnly})
	if err != nil {
		return fatal(stdout, stderr, jsonOut, exitStartup, err.Error())
	}

	if jsonOut {
		if err := report.WriteGraphJSON(stdout, result); err != nil {
			return fatal(stdout, stderr, true, exitStartup, err.Error())
		}
		return exitOK
	}
	if err := report.WriteGraph(stdout, stderr, result, report.GraphOptions{
		Version:  version,
		MaxDepth: depth,
		Colorize: report.ColorEnabled(stdout),
	}); err != nil {
		return fatal(stdout, stderr, false, exitStartup, err.Error())
	}
	return exitOK
}

func whyMain(args []string, version string, stdout, stderr io.Writer) int {
	query := ""
	flagArgs := args
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		query = args[0]
		flagArgs = args[1:]
	}

	flags := flag.NewFlagSet("deadcheck why", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.Usage = func() {
		_, _ = fmt.Fprintln(stderr, "Usage:")
		_, _ = fmt.Fprintln(stderr, "  deadcheck why [flags] <dependency> [path]")
		_, _ = fmt.Fprintln(stderr, "\nFlags:")
		flags.PrintDefaults()
	}

	var (
		jsonOut           bool
		productionOnly    bool
		pathFlag          string
		ecosystemValue    string
		dependencyVersion string
		maxPaths          int
		timeout           time.Duration
	)

	flags.BoolVar(&jsonOut, "json", false, "emit dependency paths as JSON")
	flags.BoolVar(&productionOnly, "production-only", false, "exclude npm devDependencies from path analysis")
	flags.StringVar(&pathFlag, "path", "", "target directory to inspect")
	flags.StringVar(&ecosystemValue, "ecosystem", "", "limit matches to go, npm, or pypi")
	flags.StringVar(&dependencyVersion, "dependency-version", "", "limit matches to an exact dependency version")
	flags.IntVar(&maxPaths, "max-paths", 10, "maximum causal paths per match (1-100)")
	flags.DurationVar(&timeout, "timeout", 30*time.Second, "dependency path resolution timeout")

	if err := flags.Parse(flagArgs); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return fatal(stdout, stderr, jsonOut, exitUsage, err.Error())
	}

	positional := flags.Args()
	if query == "" {
		if len(positional) == 0 {
			return fatal(stdout, stderr, jsonOut, exitUsage, "expected a dependency name")
		}
		query = positional[0]
		positional = positional[1:]
	}
	query = strings.TrimSpace(query)
	if query == "" {
		return fatal(stdout, stderr, jsonOut, exitUsage, "dependency name must not be empty")
	}
	target, err := resolveTarget(pathFlag, positional)
	if err != nil {
		return fatal(stdout, stderr, jsonOut, exitUsage, err.Error())
	}
	ecosystem, ok := parseEcosystem(ecosystemValue)
	if !ok {
		return fatal(stdout, stderr, jsonOut, exitUsage, "invalid --ecosystem; expected go, npm, pypi, or pip")
	}
	if maxPaths < 1 || maxPaths > 100 {
		return fatal(stdout, stderr, jsonOut, exitUsage, "--max-paths must be between 1 and 100")
	}
	if timeout <= 0 {
		return fatal(stdout, stderr, jsonOut, exitUsage, "--timeout must be greater than 0")
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	graphResult, err := graph.New().Build(ctx, target, graph.Options{ProductionOnly: productionOnly})
	if err != nil {
		return fatal(stdout, stderr, jsonOut, exitStartup, err.Error())
	}
	result := graph.Explain(graphResult, graph.ExplainOptions{
		Query:     query,
		Version:   dependencyVersion,
		Ecosystem: ecosystem,
		MaxPaths:  maxPaths,
	})

	if jsonOut {
		if err := report.WriteWhyJSON(stdout, result); err != nil {
			return fatal(stdout, stderr, true, exitStartup, err.Error())
		}
	} else if err := report.WriteWhy(stdout, stderr, result, report.WhyOptions{
		Version:  version,
		Colorize: report.ColorEnabled(stdout),
	}); err != nil {
		return fatal(stdout, stderr, false, exitStartup, err.Error())
	}
	if result.MatchCount == 0 {
		return exitThreshold
	}
	return exitOK
}

func parseEcosystem(value string) (model.Ecosystem, bool) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "":
		return "", true
	case "go":
		return model.EcosystemGo, true
	case "npm":
		return model.EcosystemNPM, true
	case "pypi", "pip":
		return model.EcosystemPyPI, true
	default:
		return "", false
	}
}

func initMain(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		return fatal(stdout, stderr, false, exitUsage, "expected init target; supported target: ci")
	}
	switch args[0] {
	case "ci":
		return initCI(args[1:], stdout, stderr)
	default:
		return fatal(stdout, stderr, false, exitUsage, "unsupported init target; supported target: ci")
	}
}

func initCI(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("deadcheck init ci", flag.ContinueOnError)
	flags.SetOutput(stderr)

	var (
		pathFlag       string
		schedule       string
		failBelow      int
		productionOnly bool
		force          bool
	)

	flags.StringVar(&pathFlag, "path", "", "target repository directory")
	flags.StringVar(&schedule, "schedule", "0 14 * * 1", "GitHub Actions cron schedule")
	flags.IntVar(&failBelow, "fail-below", 80, "workflow scan threshold")
	flags.BoolVar(&productionOnly, "production-only", false, "exclude npm devDependencies in the workflow scan")
	flags.BoolVar(&force, "force", false, "overwrite an existing deadcheck workflow")

	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return fatal(stdout, stderr, false, exitUsage, err.Error())
	}

	target, err := resolveTarget(pathFlag, flags.Args())
	if err != nil {
		return fatal(stdout, stderr, false, exitUsage, err.Error())
	}

	path, err := ci.InitWorkflow(ci.Options{
		Path:           target,
		Schedule:       schedule,
		FailBelow:      failBelow,
		ProductionOnly: productionOnly,
		Force:          force,
	})
	if err != nil {
		return fatal(stdout, stderr, false, exitStartup, err.Error())
	}

	_, _ = fmt.Fprintf(stdout, "Created %s\n", path)
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

func execute(ctx context.Context, cfg Config, stdin io.Reader, stdout, stderr io.Writer) error {
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
	scanFn := func(runCtx context.Context) (model.ScanResult, error) {
		scanCtx, cancel := context.WithTimeout(runCtx, cfg.Timeout)
		defer cancel()
		return scan.Scan(scanCtx, cfg.Path)
	}

	interactive := !cfg.JSON && !cfg.NoTUI && tui.Enabled(stdin, stdout)
	var (
		result model.ScanResult
		err    error
	)
	if interactive {
		result, err = tui.Run(ctx, stdin, stdout, tui.Options{
			Version:     cfg.Version,
			Path:        cfg.Path,
			MinSeverity: cfg.MinSeverity,
		}, scanFn)
		if errors.Is(err, tui.ErrCanceled) {
			return nil
		}
	} else {
		result, err = scanFn(ctx)
	}
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
	} else if !interactive {
		if err := report.WriteTable(stdout, stderr, result, report.TableOptions{
			Version:     cfg.Version,
			MinSeverity: cfg.MinSeverity,
			Colorize:    report.ColorEnabled(stdout),
		}); err != nil {
			return err
		}
	}

	if cfg.GitHubSummary {
		if err := report.WriteGitHubSummaryFromEnv(result); err != nil {
			return err
		}
	}

	if cfg.FailBelow > 0 && result.Score < cfg.FailBelow {
		return &ExitError{Code: exitThreshold}
	}
	return nil
}
