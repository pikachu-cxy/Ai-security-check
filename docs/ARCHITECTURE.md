# AI Security Runtime architecture

## Product philosophy

The coding agent writes code. This local runtime checks it, explains findings in plain language, suggests a fix task, and verifies the result. This is a modular monolith with no SaaS component in the first release.

```text
CLI / MCP / Git hook
        │
SecurityRuntime.scan(path, mode)
        │
GitService → TargetDetector → ScannerRegistry plan
                              │
                  Semgrep / Gitleaks / Trivy
                              │
             FindingNormalizer → dedupe → RiskEngine
                              │
                         SQLite store
```

## Core and local runner

`models.py` defines target, scan, scanner run, and finding contracts. `GitService` owns diff scope. `TargetDetector` recognizes languages and ecosystems. `ScannerRegistry` selects adapters by capability. `SecurityRuntime` orchestrates the same pipeline for every interface. `FindingNormalizer` creates readable titles and redacts evidence; `RiskEngine` alone decides SAFE, REVIEW, or BLOCKED. A HIGH label alone does not block: confidence and supporting evidence also matter.

QUICK uses staged/unstaged/untracked files. FEATURE adds the diff from a base branch. RELEASE scans the project. Each scanner run records status, reason, finding count, and duration. A failed scanner does not stop the scan. Results record total duration.

## Scanner plugins

Adapters implement `supports(profile, context)` and `scan(context, normalizer)`. They launch local binaries with argument arrays, bounded output, and timeouts. Semgrep uses a packaged local rule file and metrics are disabled. Gitleaks reports to a temporary file and its secret values are never copied into Findings. Trivy uses local database mode. No adapter runs application code, package scripts, or installs dependencies.

## Interfaces

The CLI offers doctor, scan, MCP startup, and hook installation. MCP uses the official Python SDK over local stdio and exposes five tools. The pre-commit hook invokes the same CLI with staged scope; it does not contain scanning logic. Future CI and agent-specific hooks should do the same.

## Storage and AI

`ScanStore` is a protocol; `SQLiteStore` is the initial implementation. It stores ScanResult and Findings for later MCP lookup. `AIProvider` and `ContextProvider` are interfaces. The first release uses deterministic fix tasks, with no AI key required. The local context provider limits extraction to nearby lines and passes it through `SecretRedactor`.

## Privacy and cloud

There is no cloud client in the scan path. `DisabledCloudSync` is the default adapter and performs no I/O. Future sync may send scan metadata, finding metadata, risk status, and scanner status. It must not send complete files by default. AI providers must receive only bounded, redacted context. The scanner tools may have their own update or telemetry behavior; Semgrep metrics are explicitly disabled, and Trivy database updates are disabled during scanning.

## Future targets

`TargetType` reserves `AI_APP`, `AI_SKILL`, `WEB`, and `MOBILE_APP`. Future AI app profiling can describe providers, models, RAG, memory, tools, and sensitive actions. Future skill profiling can inspect SKILL.md, tool permissions, shell, file, network, and secret access. They should add profilers and scanner adapters without changing CLI or MCP scan logic.
