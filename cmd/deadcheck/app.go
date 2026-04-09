package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/tuntufye/deadcheck/internal/model"
	"github.com/tuntufye/deadcheck/internal/report"
	"github.com/tuntufye/deadcheck/internal/registry"
	"github.com/tuntufye/deadcheck/internal/scanner"
)

type Config struct {
	Path        string
	MinSeverity model.Severity
	Workers     int
	Timeout     time.Duration
	JSON        bool
	FailBelow   int
	Version     string
}

type ExitError struct {
	Code    int
	Message string
}

func (e *ExitError) Error() string {
	return e.Message
}

func execute(ctx context.Context, cfg Config) error {
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

	scan := scanner.New(httpClient, registry.URLsFromEnv(), cfg.Workers)
	result, err := scan.Scan(ctx, cfg.Path)
	if err != nil {
		if errors.Is(err, scanner.ErrNoSupportedManifest) {
			return &ExitError{Code: exitStartup, Message: err.Error()}
		}
		return err
	}

	if cfg.JSON {
		if err := report.WriteJSON(os.Stdout, result); err != nil {
			return err
		}
	} else {
		if err := report.WriteTable(os.Stdout, os.Stderr, result, report.TableOptions{
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
