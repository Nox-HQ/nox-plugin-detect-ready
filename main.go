package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"

	pluginv1 "github.com/nox-hq/nox/gen/nox/plugin/v1"
	"github.com/nox-hq/nox/sdk"
)

var version = "dev"

// Compiled regex patterns for detection readiness checks.
var (
	// DETECT-001: Structured logging library detection.
	reStructuredLogging = regexp.MustCompile(`(?i)(go\.uber\.org/zap|sirupsen/logrus|log/slog|slog\.|zap\.|logrus\.|winston|pino|structlog|bunyan|log4j|logback|serilog|nlog)`)

	// DETECT-002: Security event logging detection.
	reSecurityEventLog = regexp.MustCompile(`(?i)(log\.?(warn|error|info|debug)?\(?.*(auth(entication|orization)?\s*(fail|denied|error|invalid)|login\s*(fail|attempt|error)|permission\s*(denied|error|reject)|access\s*(denied|reject|unauthori)|invalid\s*(token|credential|password|session)|brute\s*force|rate\s*limit|input\s*validation\s*(fail|error))|(authentication_failure|authorization_failure|login_failed|access_denied|invalid_token|permission_denied))`)

	// DETECT-003: Monitoring/metrics library detection.
	reMonitoringLib = regexp.MustCompile(`(?i)(prometheus|promhttp|statsd|datadog|opentelemetry|otel|micrometer|newrelic|cloudwatch|stackdriver|influxdb|grafana_?agent|telegraf|collectd)`)

	// DETECT-004: Error tracking service detection.
	reErrorTracking = regexp.MustCompile(`(?i)(sentry|bugsnag|rollbar|airbrake|honeybadger|raygun|trackjs|logrocket|errorception|getsentry|sentry_?dsn|sentry\.init|raven)`)
)

// sourceExtensions lists file extensions to scan.
var sourceExtensions = map[string]bool{
	".go": true,
	".py": true,
	".js": true,
	".ts": true,
}

// configExtensions lists config file extensions to scan.
var configExtensions = map[string]bool{
	".yaml": true,
	".yml":  true,
	".json": true,
	".toml": true,
}

// allExtensions merges source and config extensions.
var allExtensions = func() map[string]bool {
	m := make(map[string]bool)
	for k, v := range sourceExtensions {
		m[k] = v
	}
	for k, v := range configExtensions {
		m[k] = v
	}
	return m
}()

// skippedDirs contains directory names to skip during recursive walks.
var skippedDirs = map[string]bool{
	".git":         true,
	"vendor":       true,
	"node_modules": true,
	"__pycache__":  true,
	".venv":        true,
	"dist":         true,
	"build":        true,
}

// detectContext tracks workspace-level detection readiness indicators.
type detectContext struct {
	hasStructuredLogging bool
	hasSecurityEventLog  bool
	hasMonitoringLib     bool
	hasErrorTracking     bool
}

func buildServer() *sdk.PluginServer {
	manifest := sdk.NewManifest("nox/detect-ready", version).
		Capability("detect-ready", "Checks detection readiness through logging, monitoring, and error tracking").
		Tool("scan", "Scan source and config files for detection readiness indicators", true).
		Done().
		Safety(sdk.WithRiskClass(sdk.RiskPassive)).
		Build()

	return sdk.NewPluginServer(manifest).
		HandleTool("scan", handleScan)
}

func handleScan(ctx context.Context, req sdk.ToolRequest) (*pluginv1.InvokeToolResponse, error) {
	workspaceRoot, _ := req.Input["workspace_root"].(string)
	if workspaceRoot == "" {
		workspaceRoot = req.WorkspaceRoot
	}

	resp := sdk.NewResponse()

	if workspaceRoot == "" {
		return resp.Build(), nil
	}

	dc := &detectContext{}

	err := filepath.WalkDir(workspaceRoot, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if d.IsDir() {
			if skippedDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}

		ext := filepath.Ext(path)
		if !allExtensions[ext] {
			return nil
		}

		// Also check special config file names.
		lowerName := strings.ToLower(d.Name())
		if lowerName == "go.mod" || lowerName == "go.sum" || lowerName == "package.json" || lowerName == "requirements.txt" || lowerName == "pyproject.toml" {
			scanFileForDetection(dc, path)
			return nil
		}

		scanFileForDetection(dc, path)
		return nil
	})
	if err != nil && err != context.Canceled {
		return nil, fmt.Errorf("walking workspace: %w", err)
	}

	emitDetectionFindings(resp, dc)

	return resp.Build(), nil
}

// scanFileForDetection scans a single file for detection readiness indicators.
func scanFileForDetection(dc *detectContext, filePath string) {
	f, err := os.Open(filePath)
	if err != nil {
		return
	}
	defer func() { _ = f.Close() }()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()

		if reStructuredLogging.MatchString(line) {
			dc.hasStructuredLogging = true
		}
		if reSecurityEventLog.MatchString(line) {
			dc.hasSecurityEventLog = true
		}
		if reMonitoringLib.MatchString(line) {
			dc.hasMonitoringLib = true
		}
		if reErrorTracking.MatchString(line) {
			dc.hasErrorTracking = true
		}

		// Early exit if all indicators are found.
		if dc.hasStructuredLogging && dc.hasSecurityEventLog && dc.hasMonitoringLib && dc.hasErrorTracking {
			return
		}
	}
}

// emitDetectionFindings emits findings for missing detection components.
func emitDetectionFindings(resp *sdk.ResponseBuilder, dc *detectContext) {
	if !dc.hasStructuredLogging {
		resp.Finding(
			"DETECT-001",
			sdk.SeverityMedium,
			sdk.ConfidenceHigh,
			"No structured logging library detected: missing logrus, zap, slog, winston, pino, or structlog",
		).
			WithMetadata("category", "detection_readiness").
			WithMetadata("remediation", "Add a structured logging library such as zap (Go), winston (Node.js), or structlog (Python)").
			Done()
	}

	if !dc.hasSecurityEventLog {
		resp.Finding(
			"DETECT-002",
			sdk.SeverityHigh,
			sdk.ConfidenceMedium,
			"Security events not logged: authentication failures, permission denials, and input validation errors should be logged",
		).
			WithMetadata("category", "detection_readiness").
			WithMetadata("remediation", "Add logging for authentication failures, authorization denials, and input validation errors").
			Done()
	}

	if !dc.hasMonitoringLib {
		resp.Finding(
			"DETECT-003",
			sdk.SeverityMedium,
			sdk.ConfidenceMedium,
			"No monitoring or metrics library detected: missing prometheus, statsd, datadog, or opentelemetry",
		).
			WithMetadata("category", "detection_readiness").
			WithMetadata("remediation", "Add a metrics collection library such as Prometheus client, StatsD, or OpenTelemetry").
			Done()
	}

	if !dc.hasErrorTracking {
		resp.Finding(
			"DETECT-004",
			sdk.SeverityMedium,
			sdk.ConfidenceHigh,
			"No error tracking service detected: missing sentry, bugsnag, rollbar, or airbrake references",
		).
			WithMetadata("category", "detection_readiness").
			WithMetadata("remediation", "Integrate an error tracking service such as Sentry, Bugsnag, or Rollbar").
			Done()
	}
}

func main() {
	os.Exit(run())
}

func run() int {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	srv := buildServer()
	if err := srv.Serve(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "nox-plugin-detect-ready: %v\n", err)
		return 1
	}
	return 0
}
