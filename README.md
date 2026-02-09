# nox-plugin-detect-ready

**Detection readiness assessment for security observability.**

## Overview

`nox-plugin-detect-ready` evaluates whether a codebase has the foundational observability infrastructure required to detect and respond to security incidents. It checks for four critical pillars of detection readiness: structured logging, security event logging, monitoring/metrics collection, and error tracking services.

Security breaches that go undetected for months are often the result of missing observability infrastructure rather than missing firewalls. This plugin answers a fundamental question: "If a security incident happens right now, does this codebase have the instrumentation to detect it?" By scanning source code, configuration files, and dependency manifests for evidence of logging libraries, security event patterns, metrics exporters, and error tracking integrations, it identifies observability gaps before they become blind spots during an incident.

The plugin belongs to the **Incident Readiness** track and operates with a passive risk class. It performs a workspace-level assessment, producing one finding per missing capability rather than per-file findings. If all four detection pillars are present, the plugin produces zero findings.

## Use Cases

### Pre-Production Readiness Check

A team is preparing to launch a new microservice. Before the production readiness review, they run the detect-ready plugin to verify that the service has structured logging (zap), Prometheus metrics, Sentry error tracking, and security event logging for authentication failures. The plugin flags that security event logging is missing, prompting the team to add authentication failure logging before go-live.

### SOC 2 Compliance Evidence

An organization preparing for SOC 2 Type II certification needs to demonstrate that all production services have adequate monitoring and logging. The detect-ready plugin is run across all repositories as part of the compliance audit, producing a clear inventory of which services have detection gaps. The findings directly map to SOC 2 control requirements for incident detection.

### Incident Postmortem Action Items

After a security incident where the team discovered that a compromised service had no error tracking or metrics collection, the CISO mandates that all services must pass a detection readiness check. The plugin is added to the CI pipeline for every repository, ensuring that new services cannot be deployed without baseline observability infrastructure.

### Platform Team Governance

A platform engineering team wants to ensure all teams adopt the organization's observability stack (OpenTelemetry, Sentry, structured logging). The detect-ready plugin provides an automated check that verifies each service integrates with the required tools, without requiring manual review.

## 5-Minute Demo

### Prerequisites

- Go 1.25+
- [Nox](https://github.com/nox-hq/nox) installed

### Quick Start

1. **Install the plugin**

   ```bash
   nox plugin install nox-hq/nox-plugin-detect-ready
   ```

2. **Create a test project with observability gaps**

   ```bash
   mkdir -p demo-detect-ready && cd demo-detect-ready
   ```

   Create `main.go`:

   ```go
   package main

   import (
       "fmt"
       "log"
       "net/http"
   )

   func handler(w http.ResponseWriter, r *http.Request) {
       log.Printf("request received: %s %s", r.Method, r.URL.Path)
       fmt.Fprintf(w, "Hello, World!")
   }

   func main() {
       http.HandleFunc("/", handler)
       log.Fatal(http.ListenAndServe(":8080", nil))
   }
   ```

   Note: This project uses Go's standard `log` package (not structured logging), has no security event logging, no metrics library, and no error tracking.

3. **Run the scan**

   ```bash
   nox scan --plugin nox/detect-ready .
   ```

4. **Review findings**

   ```
   DETECT-001  MED/HIGH   No structured logging library detected: missing logrus, zap, slog, winston, pino, or structlog
   DETECT-002  HIGH/MED   Security events not logged: authentication failures, permission denials, and input validation errors should be logged
   DETECT-003  MED/MED    No monitoring or metrics library detected: missing prometheus, statsd, datadog, or opentelemetry
   DETECT-004  MED/HIGH   No error tracking service detected: missing sentry, bugsnag, rollbar, or airbrake references

   4 findings (1 high, 3 medium)
   ```

## Rules

| Rule ID    | Description                                                                     | Severity | Confidence | CWE |
|------------|---------------------------------------------------------------------------------|----------|------------|-----|
| DETECT-001 | No structured logging library detected (zap, logrus, slog, winston, pino, etc.) | MEDIUM   | HIGH       | --  |
| DETECT-002 | Security events not logged (auth failures, permission denials, input validation) | HIGH     | MEDIUM     | --  |
| DETECT-003 | No monitoring/metrics library detected (Prometheus, StatsD, Datadog, OTel)      | MEDIUM   | MEDIUM     | --  |
| DETECT-004 | No error tracking service detected (Sentry, Bugsnag, Rollbar, Airbrake)         | MEDIUM   | HIGH       | --  |

### Detection Patterns

| Category           | Libraries / Patterns Detected                                                    |
|--------------------|----------------------------------------------------------------------------------|
| Structured Logging | zap, logrus, slog, winston, pino, structlog, bunyan, log4j, logback, serilog, nlog |
| Security Events    | authentication failure/denied, login fail/attempt, permission denied, access denied, invalid token/credential/password, brute force, rate limit |
| Monitoring/Metrics | Prometheus, promhttp, StatsD, Datadog, OpenTelemetry, Micrometer, New Relic, CloudWatch, InfluxDB, Grafana Agent, Telegraf |
| Error Tracking     | Sentry, Bugsnag, Rollbar, Airbrake, Honeybadger, Raygun, TrackJS, LogRocket      |

## Supported Languages / File Types

| Type             | Extensions                             |
|------------------|----------------------------------------|
| Source files      | `.go`, `.py`, `.js`, `.ts`            |
| Config files      | `.yaml`, `.yml`, `.json`, `.toml`     |
| Dependency files  | `go.mod`, `go.sum`, `package.json`, `requirements.txt`, `pyproject.toml` |

## Configuration

The plugin uses Nox's standard configuration. No additional configuration is required.

```yaml
# .nox.yaml (optional)
plugins:
  nox/detect-ready:
    enabled: true
```

Directories automatically skipped during scanning: `.git`, `vendor`, `node_modules`, `__pycache__`, `.venv`, `dist`, `build`.

## Installation

### Via Nox (recommended)

```bash
nox plugin install nox-hq/nox-plugin-detect-ready
```

### Standalone

```bash
go install github.com/nox-hq/nox-plugin-detect-ready@latest
```

### From source

```bash
git clone https://github.com/nox-hq/nox-plugin-detect-ready.git
cd nox-plugin-detect-ready
make build
```

## Development

```bash
# Build the plugin binary
make build

# Run all tests
make test

# Run linter
make lint

# Build Docker image
docker build -t nox-plugin-detect-ready .

# Clean build artifacts
make clean
```

## Architecture

The plugin operates as a Nox plugin server communicating over stdio using the Nox Plugin SDK. The scan uses an accumulator pattern:

1. **File Walk** -- Recursively walks the workspace, processing source files, config files, and dependency manifests. Standard non-source directories are skipped.
2. **Pattern Accumulation** -- Each file is scanned line-by-line against four compiled regex patterns, one per detection category. When a pattern matches, the corresponding boolean flag in the `detectContext` is set to `true`. Once all four flags are set, the scanner short-circuits and stops reading further files.
3. **Gap Emission** -- After the walk completes, the `emitDetectionFindings` function checks each boolean flag. For each flag that remains `false`, a finding is emitted describing the missing capability and providing a specific remediation recommendation.

This design produces at most four findings per workspace -- one per missing detection pillar -- rather than per-file findings, reflecting the workspace-level nature of detection readiness.

## Contributing

Contributions are welcome. Please open an issue or pull request on [GitHub](https://github.com/nox-hq/nox-plugin-detect-ready).

When adding new detection categories:
1. Define a new compiled regex pattern for the category.
2. Add a boolean field to `detectContext`.
3. Add matching logic in `scanFileForDetection` with early-exit optimization.
4. Add a finding emission block in `emitDetectionFindings` with a clear remediation message.

## License

Apache-2.0
