# AI Security Runtime

Current status and next steps: [development progress](docs/DEVELOPMENT_PROGRESS.md)
and [personal/free and enterprise roadmap](docs/PRODUCT_ROADMAP.md).
The progress document distinguishes source implementation, isolated checks,
current package acceptance and pending Desktop trials.

**Windows rule-foundation experience (R2.2):** [installation and six-step checklist](docs/WINDOWS_EXPERIENCE.md).
Use natural language with the companion Security Review Skill and existing MCP to
scan, review, fix an authorized task and verify with the original scanner. Explicit
review works without Hooks; new Desktop behavior requires personal acceptance.
Current work adds the Java/JavaScript/TypeScript rule foundation. Release and CI
work remain paused; this local build is not a published Release.

Rule Program v1 is capability-led: 25 detection capabilities, 2 CORE and 23
VALIDATED. First-party rule pack 1.3.0 contains 55 installed Semgrep rules,
47 default-on, including 15 Python rules and 6 shared JavaScript/TypeScript rules.
The 8 legacy Java EXPERIMENTAL rules remain default-off. These counts describe
source coverage, not production accuracy or current Desktop acceptance.
See the [rule foundation and limitations](docs/RULE_FOUNDATION.md),
[Rule Program](docs/RULE_PROGRAM.md) and [coverage matrix](docs/RULE_COVERAGE_MATRIX.md).

CLI scans show actual preparation and scanner states on **stderr** after a 500 ms
delay. Final human results and JSON remain on **stdout**. Interactive terminals
refresh elapsed time every second; redirected logs receive a heartbeat every
10 seconds. Short scans stay quiet. Progress never predicts percentages.

Use `security-check scan --mode release --json --no-progress` for a quiet script
result, or `--verbose` to include capabilities that do not apply. Human scan
results are Chinese; JSON enums remain unchanged. Ctrl+C cancels the scan and
stops external engine processes. Library and MCP calls do not enable CLI progress.

**English** | [简体中文](README.zh-CN.md)

> **Agent writes. Security Runtime verifies.**

AI Security Runtime is a local-first security layer for AI coding workflows. It checks the code an AI agent writes and exposes the same security capabilities through the CLI, verified host integrations, and Generic MCP.

- **Local-first:** project source stays on your machine by default.
- **Codex:** Global Runtime Integration is **DESKTOP VERIFIED**.
- **Cursor:** detection and advisory remediation are **DESKTOP VERIFIED** on the observed path.
- **Generic MCP:** remains available for MCP-compatible clients.
- **CLI:** works without any AI coding tool and is suitable for local scripts and future CI/CD use.
- **Fail clearly:** missing scanners reduce coverage instead of claiming the project is safe.

> Developer Alpha. NO_FINDINGS means no candidate was found within the executed rules and scope; it does not prove the project is secure.

Detection quality is being hardened against real-world and independently labelled corpora; complex interprocedural and wrapper flows remain limited.

## Rule Program v1

The product speaks in capabilities rather than raw rule-file counts:

- 25 detection capabilities: 2 CORE and 23 VALIDATED
- 55 total installed Semgrep rules in pack 1.3.0; 47 default-on
- 8 legacy Java EXPERIMENTAL rules, default-off
- 15 Python rules
- 6 shared JavaScript/TypeScript advisory rules, default-on

The historical Java foundation below is a subset of the current capability
catalog; current source counts and known gaps are recorded in
[development progress](docs/DEVELOPMENT_PROGRESS.md):

| Capability | Maturity |
| --- | --- |
| TLS Hostname Verification Disabled | CORE |
| Hardcoded Secret | CORE |
| SQL Injection | VALIDATED |
| Command Injection | VALIDATED |
| SSRF | VALIDATED |
| Path Traversal | VALIDATED |
| Arbitrary File Read | VALIDATED |
| Arbitrary File Write | VALIDATED |
| XXE | VALIDATED |
| Unsafe Deserialization | VALIDATED |

```text
Capability → underlying scanner rules → Finding Family / Episode
           → Policy → remediation / proof
```

The synthetic R0 corpus reports 46 TP / 28 TN / 0 FP / 0 FN. This is not
production-grade accuracy.

See [Rule Program v1](docs/RULE_PROGRAM.md) and the [coverage matrix](docs/RULE_COVERAGE_MATRIX.md)
for the detailed mapping, acceptance evidence, and limitations.

---

## Installation

Package-manager installation is being prepared for the next Developer Alpha release.
These commands are not available until the GitHub assets and external listings are published.

### Windows

```powershell
winget install --id PikachuCXY.AISecurityRuntime -e
```

### macOS / Linux x64

```bash
brew install pikachu-cxy/tap/ai-security-runtime
```

The standalone Runtime includes its Python runtime. Codex installation and
upgrades prepare the compatible security engines, bundled rules and current
vulnerability data in one product operation. No system Python, pip or venv is
required. Run inside your Git project:

```bash
security-check --version
security-check doctor
security-check scan --mode quick
security-check setup cursor
security-check setup workbuddy
security-check install codex
```

For Codex, see [setup and integration details](docs/CODEX_INTEGRATION.md). The
current Global Runtime Integration status is **DESKTOP VERIFIED**.

### Install or upgrade Codex protection

Run the same command from the new Runtime package for an initial installation,
upgrade, or preparation retry:

```bash
security-check install codex
```

The command installs the global connection and companion Skill, verifies the
bundled rule pack, prepares the default engines at product-tested versions, and
refreshes missing or expired vulnerability data. Valid compatible caches are
reused; engines do not blindly follow the latest third-party release. Tool and
data preparation stays in the Runtime's per-user storage and does not install
dependencies or execute code from the protected project. Optional fallback
engines remain on demand.

Installation distinguishes configured files from scanning readiness. If a
download or verification fails, configuration may already be installed, but the
product reports that protection is not ready and exits with code 2. Retry
`security-check install codex` after resolving the reported connection or cache
problem; individual tool commands are advanced diagnostics, not a normal
installation step. A completed install still requires the host to reload its
connection and accept its own Hook trust prompt.

```bash
security-check install codex --offline
```

Offline installation only verifies and reuses local compatible engines, rules
and unexpired vulnerability data. Missing, damaged or expired assets remain an
explicit incomplete preparation result. `security-check setup codex` only
configures the connection and Skill; it does not download tools or establish
scanning readiness. Quick dependency checks and automatic Hooks remain offline.
This release refreshes data during product installation or a repeated install;
it does not yet provide a background data-update scheduler.

## 2. Run your first CLI scan

Run AI Security Runtime **inside a Git project**.

For a safe first test, copy the included intentionally vulnerable sample into a temporary Git repository.

### Windows PowerShell

From the `Ai-security-check` directory:

```powershell
New-Item -ItemType Directory -Force ..\security-runtime-demo | Out-Null
Copy-Item -Recurse .\samples\vulnerable-python\* ..\security-runtime-demo\
cd ..\security-runtime-demo
git init
```

Check the environment:

```bash
security-check doctor
```

Then scan:

```bash
security-check scan --mode quick
```

Codex installation prepares the default tools and vulnerability data before use. Other permitted online scan flows prepare only engines selected by the scan plan. A quick scan with no changes downloads nothing. Source-only edits do not repeat dependency checks; added, changed or removed manifests/lockfiles request local offline dependency checks against the remaining inputs in the affected scope. Missing or expired dependency assets produce incomplete coverage; Codex users retry the product installation to refresh them. Downloads in permitted preparation flows are verified before use and do not require a system-wide PATH change.

A successful test should:

1. identify the current workspace;
2. run the available local security engines;
3. report findings from the intentionally vulnerable sample;
4. show scan coverage such as `FULL` or `PARTIAL`.

Machine-readable output is available with:

```bash
security-check scan --mode quick --json
```

### Scan modes

```bash
security-check scan --mode quick
security-check scan --mode feature
security-check scan --mode release
```

- **quick** — changed and untracked files; changed dependency manifests/lockfiles also trigger scoped dependency checks.
- **feature** — branch diff against main/master plus local changes, with the same change-triggered dependency checks.
- **release** — tracked and untracked project files for broader release review.

Automatic Hooks also check changed dependency inputs, using local offline tools and data. They never install the target project's dependencies, run its package manager or build it. Missing local tools/data leave dependency coverage incomplete; they do not establish that dependencies are safe. CLI quick, feature and staged scans still require Git; automatic Hooks retain their existing source-directory support.

Dependency discovery and planning share the recognized Python, JavaScript, Maven/Gradle and Go manifest/lockfile names. Filename recognition does not attest a complete resolved dependency graph: provider inventory and coverage evidence remain authoritative. Removing an input requests reevaluation of the remaining inventory; it does not prove that installed/runtime dependencies were removed.

---

# Connect an AI coding tool

AI Security Runtime exposes these MCP tools:

- `scan_diff`
- `scan_project`
- `get_findings`
- `generate_fix`
- `verify`

`generate_fix` returns a coding task; it does not silently edit source code.

The recommended workflow is:

```text
AI edits code
    ↓
scan_diff
    ↓
Finding
    ↓
AI fixes code
    ↓
verify
    ↓
RESOLVED
```

---

## Cursor — production status and setup

Inside the Git project you want to protect:

```bash
security-check setup cursor
```

Expected result:

```text
AI Security Runtime

Workspace
✓ <your-project>

Connecting Cursor...
✓ Cursor configuration written
✓ Runtime MCP self-test passed
○ Cursor client connection not confirmed yet
Restart Cursor to load the project connection.

Code stays local.
```

The Runtime can manage a project-level connection in:

```text
.cursor/mcp.json
```

It preserves existing MCP servers and only manages its own `ai-security-runtime` entry.

Restart Cursor if requested.

Then ask Cursor:

> Use AI Security Runtime to scan the current Git diff. Show me the findings. If there are security issues, fix them and call verify afterwards.

The current production Cursor events are:

```text
sessionStart
afterFileEdit
afterShellExecution
stop
```

Current status:

```text
Detection Runtime       = DESKTOP VERIFIED
First-Scan Attribution   = DESKTOP VERIFIED
Finding / Policy         = DESKTOP VERIFIED
Advisory Remediation     = DESKTOP VERIFIED
Native Chat Feedback     = HOST_CAPABILITY_UNAVAILABLE_ON_OBSERVED_PATH
Automatic Continuation   = PENDING_HOST_CAPABILITY
```

`postToolUse` and `additional_context` are not part of the current production
Cursor path. A configuration file being written is not itself Desktop verification.

Check integration state:

```bash
security-check integrations
```

---

## WorkBuddy — one-command setup

Inside the Git project:

```bash
security-check setup workbuddy
```

The Runtime manages the project-level WorkBuddy MCP configuration and preserves other MCP entries.

Setup writes `<project>/.workbuddy/mcp.json`, as documented in the
[WorkBuddy MCP guide](https://www.codebuddy.ai/docs/zh/workbuddy/From-Beginner-to-Expert-Guide/Function-Description/MCP-Guide).
Some desktop versions expose `%USERPROFILE%/.workbuddy-ai/mcp.json` in their UI.
The Runtime does not assume that writing a project config proves that your desktop
version loaded it. If your version uses the global UI, use `security-check mcp
config --json` and register the generated workspace-bound entry there. Use a
separate entry/server session per workspace; do not reuse one project's binding
for another project. Automatic global registration is not implemented in this alpha.

`integrations` shows the configuration path, configuration status, Runtime
self-test, and last real MCP invocation separately. `NEEDS_RESTART` means that
configuration and self-test succeeded but a host tool invocation is still pending.
Only an actual tool invocation records `CONNECTED`; Runtime self-tests do not.
This records MCP traffic attributed by the configured integration identifier,
not a probe of the application's UI.

New Runtime-owned project config files use a reversible block in `.git/info/exclude`.
Shared `.gitignore` and pre-existing mixed user config remain untouched.

Restart WorkBuddy if requested.

Then ask WorkBuddy:

> Use AI Security Runtime to scan the current Git diff and show me the security findings.

After confirming `scan_diff` works, test:

> Fix the reported issue and use AI Security Runtime to verify the fix.

Check status with:

```bash
security-check integrations
```

---

## Codex Global Runtime Integration

Codex Global Runtime Integration = **DESKTOP VERIFIED**.

The verified core chain is:

```text
AI edit
  → Global Hook
  → mutation reconciliation
  → Scanner
  → Finding / Policy
  → INLINE_PREPARED remediation
  → Exact Edit Envelope
  → real Scanner proof
  → CLOSED
```

Generic MCP remains available as an interface for Codex and other MCP clients,
but it is not the only or primary Codex integration path.

Run this from the Git project you want to protect:

```bash
security-check mcp config --toml
```

For JSON-based MCP clients:

```bash
security-check mcp config --json
```

On Windows you can copy the generated JSON directly:

```bash
security-check mcp config --copy
```

The generated configuration contains:

- the absolute Runtime command;
- `mcp` arguments;
- the bound project workspace;
- the integration identifier.

Paste the generated configuration into the MCP settings of the coding tool, restart/reload that tool if necessary, and ask:

> Use AI Security Runtime to scan the current Git diff.

A Generic MCP integration is considered working only when the client can see and call the Runtime tools, not merely when the configuration text exists.

### No MCP support?

If a coding agent can execute shell commands but cannot connect to MCP, use the universal CLI fallback:

```bash
security-check scan --mode quick --json
```

---

# Recommended acceptance checklist

Use the same temporary vulnerable Git project for all clients.

| Test | Pass condition |
| --- | --- |
| CLI install | `security-check --help` works |
| Environment | `security-check doctor` identifies the correct workspace |
| CLI scan | `security-check scan --mode quick` returns real findings |
| JSON | `--json` returns parseable machine-readable output |
| Cursor | `security-check setup cursor` succeeds and Cursor can call `scan_diff` |
| WorkBuddy | `security-check setup workbuddy` succeeds and WorkBuddy can call `scan_diff` |
| Codex Global Runtime | Global Hook → reconciliation → Scanner → Policy → proof → CLOSED |
| Generic MCP | generated configuration allows the client to call Runtime tools |
| Fix loop | finding → agent fix → `verify` → `RESOLVED` |
| Workspace isolation | another repository does not reuse findings from the previous repository |
| Repeated setup | running setup repeatedly does not duplicate or damage MCP config |
| Offline reuse | already installed local tools continue to work when downloads are disabled |
| Partial coverage | one unavailable scanner does not stop the remaining scanners |

If you need to inspect details:

```bash
security-check doctor --verbose
security-check integrations --verbose
security-check tools status
```

---

# Useful commands

### Environment

```bash
security-check doctor
security-check doctor --json
security-check doctor --verbose
```

### Scanning

```bash
security-check scan --mode quick
security-check scan --mode feature
security-check scan --mode release
security-check scan --mode quick --json
```

### AI coding integrations

```bash
security-check setup
security-check setup cursor
security-check setup workbuddy

security-check integrations
security-check integrations --verbose
security-check integrations repair
security-check integrations remove cursor
security-check integrations remove workbuddy
```

### Generic MCP

```bash
security-check mcp config
security-check mcp config --json
security-check mcp config --toml
security-check mcp config --copy
```

### Managed security tools

Codex users install or update the product with `security-check install codex`.
These lower-level commands are available for diagnostics and advanced tool
management:

```bash
security-check tools status
security-check tools install --all
```

### Local usage statistics

```bash
security-check stats
```

### Git pre-commit hook

```bash
security-check hooks install pre-commit
```

### License / distribution check

```bash
security-check licenses
security-check licenses --check-distribution
```

---

# What runs locally?

Current built-in security capabilities are backed by:

- **Semgrep** — pattern-based code security using the local first-party `ai-security-core` rule pack.
- **Gitleaks** — secret detection.
- **Trivy** — independent dependency vulnerability (`vuln`) and IaC (`misconfig`) providers.
- **OSV-Scanner 2.6.0** — optional dependency fallback, prepared only after an eligible primary failure.

The Runtime chooses engines by security capability and normalizes results into one finding model.

Semgrep community/registry rules are **not** downloaded or bundled by default. The default Semgrep scan uses only this project's independently authored local rule pack.

Gitleaks, Trivy and the on-demand OSV-Scanner are resolved in this order:

```text
Explicit path
    ↓
Runtime-managed copy
    ↓
Compatible system PATH copy
    ↓
Automatic managed install
```

Offline mode disables new downloads but still allows already installed compatible local tools.

To disable downloads:

```text
SECURITY_RUNTIME_OFFLINE=1
```

---

# Coverage and result meaning

AI Security Runtime does not treat missing scanners as a clean security result.

Scan output includes coverage:

- **NONE / NO_CHANGES** — no changed files to check; no security scan executed,
  and recommendation is **NOT_ASSESSED**.
- **FULL** — applicable planned code and secret checks succeeded on the selected
  files. This describes the plan, not every security capability or every project file.
- **SCOPED** — applicable checks succeeded, but code security was not applicable
  (for example, a secret-only file change).
- **PARTIAL** — some applicable checks failed or were unavailable.
- **MINIMAL** — no applicable check succeeded.

JSON/MCP expose `execution_state`, `coverage_scope: PLANNED_FILES`, and individual
`capability_results`. `NOT_APPLICABLE` is distinct from engine failure or
unavailability; ordinary output groups these checks separately.

Release status is intended to communicate:

- **NO_FINDINGS** — the executed rules found no candidate within the stated scope.
- **REVIEW** — human or agent review is recommended.
- **BLOCKED** — the current policy found a release-blocking issue.

NO_FINDINGS does not prove project security. Historical SAFE records use this scoped wording when displayed.

## Detection quality status

```text
R1 Phase 1 — corpus and evaluation complete locally
R1 Phase 2 — bounded detection fixes complete locally
Current — Java/JS/TS rule foundation and local user experience
Release / CI — paused; no tag or Release is implied
```

The R0 synthetic corpus is not a production accuracy claim. Broader corpus
coverage and independent review are required before promoting VALIDATED
capabilities to CORE. R1 Benchmark evaluation found substantial analysis
limitations; those R1 results do not graduate the current 2 CORE and 23 VALIDATED
capabilities. See the
[Rule Program](docs/RULE_PROGRAM.md) for the supported scope and limitations.

---

# Workspace safety

The CLI, MCP server, Cursor, WorkBuddy, and pre-commit hook use the same workspace resolver.

The Runtime rejects unsafe broad roots such as:

- the user home directory;
- a drive root;
- Windows system directories.

Git projects use changed files for quick/feature and `git ls-files --cached --others
--exclude-standard` for release. Explicit scoped lists may contain files deeper
than 12 levels; depth/directory limits apply to recursive non-Git discovery.
Path escape, symlink/junction, file-count and file-size safeguards still apply.
Single-finding verification profiles only its affected file and uses its originating
scanners. Doctor reports profiling limits without hiding tool/workspace diagnostics.

MCP logs go to stderr so stdout remains available for the stdio protocol.

---

# Troubleshooting

### `No project detected`

Run the command inside a Git repository:

```bash
git init
security-check doctor
```

Or explicitly inspect a project:

```bash
security-check doctor --path <project>
```

### A scanner is missing

For Codex protection, repeat `security-check install codex` to prepare the
product's default engines and vulnerability data together. Online manual scan
flows can also prepare tools required by their scan plan; automatic Hooks and
quick dependency checks only reuse local assets.

Check status:

```bash
security-check tools status
```

For advanced component diagnosis, prepare them explicitly:

```bash
security-check tools install --all
```

### Cursor / WorkBuddy configuration changed after reinstalling the Runtime

Repair the managed connection:

```bash
security-check integrations repair
```

### Need detailed integration information

```bash
security-check integrations --verbose
security-check doctor --verbose
```

### Remove a native project connection

```bash
security-check integrations remove cursor
security-check integrations remove workbuddy
```

Only the `ai-security-runtime` entry managed by this project is removed.

---

# Local state and privacy

Scan history and integration state use a user-level local state directory.

On Windows, managed Runtime data is stored under:

```text
%LOCALAPPDATA%\AI-Security-Runtime
```

The product does not require an AI API key for CLI scanning.

Dogfood/usage state must not store full source code, secrets, private file contents, or full prompts.

---

# CI / automation

The CLI is the universal automation interface and can later be used in Jenkins, GitHub Actions, GitLab CI, or other pipelines.

A simple machine-readable invocation is:

```bash
security-check scan --mode release --json
```

The repository itself currently uses three GitHub Actions checks:

- **Runtime tests** — Windows and Ubuntu test suite.
- **Compliance** — engine license metadata, first-party rule provenance, forbidden rule sources, notices.
- **Package integrity** — builds and verifies the source/wheel distribution.

Version tags run these as sequential release gates before four native standalone builds.
Distribution changes on the feature branch also run Windows x64, Ubuntu 22.04 x64,
macOS arm64 and macOS x64 verification: first managed scanner preparation, quick
and release sample scans, plugin discovery, and a real MCP SDK stdio session.

---

# Licensing

AI Security Runtime follows a **closed-core, open-ecosystem** model:

- Runtime Core, risk/policy engines, and future advanced rules/intelligence: **Proprietary**.
- Public Plugin API and the current base `ai-security-core` rule pack: **Apache-2.0**.
- Semgrep, Gitleaks, Trivy, and other third-party components retain their own licenses.

Free use does not mean open source. Unless a component is explicitly marked Apache-2.0, the Runtime is governed by the root `LICENSE` and `EULA.md`.

See [Licensing model](LICENSING.md).

---

# Rule and license boundaries

Engine licenses and rule-pack licenses are tracked separately.

The Runtime does not bundle or automatically fetch Semgrep Community/Registry Rules.

User-provided local rules can be used with:

```bash
security-check scan --rules <directory>
```

See:

- [Third-party notices](THIRD_PARTY_NOTICES.md)
- [Source availability notice](SOURCE_OFFER.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Extension guide](docs/EXTENDING.md)

---

## Current Developer Alpha support

| Interface | Status |
| --- | --- |
| CLI | Supported |
| Cursor | Detection / Attribution / Finding-Policy / Advisory Remediation — DESKTOP VERIFIED; native feedback unavailable on observed path |
| WorkBuddy | Project setup available; Desktop invocation verified separately |
| Generic stdio MCP | Available interface |
| Codex | Global Runtime Integration — DESKTOP VERIFIED; Generic MCP also available |
| Other MCP coding tools | Generic MCP |
| Git pre-commit | Supported |
| CI/CD | CLI foundation available |

The product goal is simple:

> **Native where valuable. Generic MCP everywhere else. CLI as the universal fallback.**

## Development / Contributing

The following source installation is for developers.

### Source checkout

### Requirements

- Windows, Linux, or macOS
- Python **3.12+**
- Git

The current Developer Alpha lives on the `feature/runtime-mvp` branch.

### 1. Install

#### Windows PowerShell

```powershell
git clone -b feature/runtime-mvp https://github.com/pikachu-cxy/Ai-security-check.git
cd Ai-security-check

py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1

python -m pip install --upgrade pip
pip install -e ".[test,scanner-test,build-standalone]"
```

#### Linux / macOS

```bash
git clone -b feature/runtime-mvp https://github.com/pikachu-cxy/Ai-security-check.git
cd Ai-security-check

python3.12 -m venv .venv
source .venv/bin/activate

python -m pip install --upgrade pip
pip install -e ".[test,scanner-test,build-standalone]"
```

Confirm the CLI is installed:

```bash
security-check --help
```

---


See [distribution staging](distribution/README.md) for native builds, verification, and the first external publication steps.

## Scan failures and source directories

`doctor` reports local prerequisites using `READY` / `MISSING`. READY means required local engine prerequisites are available; actual project scans may still need project-specific or remote dependency resolution. It does not guarantee that a project scan succeeds.

`doctor --verbose` and `tools status` report Trivy vulnerability DB and Java DB separately. Java DB is `MISSING` or `READY` based on local files; checks availability is `UNKNOWN`. This release does not automatically prepare Java DB or checks data. A Maven repository HTTP 429 is reported as `MAVEN_RATE_LIMITED`, independently of local database readiness.

Release scans also accept a source directory without Git: `security-check scan --path <directory> --mode release`. In a safely recognized source directory, `doctor` and release scans can use the current directory. Quick, feature and staged scans require Git and suggest release scanning instead. Git projects use Git file lists; ordinary directories use bounded discovery with file, directory, depth, size and ignored-directory limits. Home, drive/system roots and symlinks/junctions remain protected.

Each scanner failure includes `error_code`, `error_summary`, `remediation`, optional `retry_after_seconds`, and bounded sanitized `diagnostic_detail`. CLI JSON and MCP carry the same fields. Raw stdout/stderr remain internal, bounded, and absent from scan history and MCP responses. URLs are reduced to hosts; credentials and authorization values are redacted; proxy output only says configured/not configured.

Dependency capability reports `EXECUTED` when at least one successful provider satisfies its FULL planned-inventory coverage contract, preserving failed primary history and fallback identity. Direct manifest/POM results without graph completeness proof remain `PARTIAL`. Other capabilities report `EXECUTED` when their planned required providers succeed, `PARTIAL` when success is mixed with failure/unavailability/timeout, `FAILED` when no provider succeeds and execution fails, `UNAVAILABLE` when providers cannot execute, and `NOT_APPLICABLE` for checks outside the scan scope. Findings from completed checks remain valid under partial coverage; additional issues may remain undetected. Failed preparation gives a retry command such as `security-check tools install gitleaks`. Maven rate limits suggest a local cache, mirror or later retry. Runtime never automatically runs the target project's Maven/Gradle/npm/pip/go build or dependency commands.

## Dependency providers and fallback

Gitleaks independently satisfies default SECRET_SCAN. Trivy dependency failures do not affect its separate IaC process. Eligible dependency failures (including Maven 429, network timeout, DNS/proxy failure, HTTP 5xx, resolution failure or engine unavailability) select OSV-Scanner; integrity, boundary, configuration and invariant failures are exposed without automatic fallback. JSON and MCP include `capability_details` and role/coverage metadata for every executed provider.

`tools install --all` prepares the primary engines. OSV remains `ON_DEMAND / FALLBACK` in `tools status`; `doctor --verbose` reports its availability without requiring it for readiness or downloading it. `tools install osv-scanner` explicitly prepares the pinned official, checksum-verified release. OSV online scans query deps.dev/OSV.dev using dependency identity information. Offline scanning requires both a locally compatible engine and ecosystem databases at `<data-dir>/data/osv/osv-scalibr/<ecosystem>/all.zip`; Runtime does not download them in offline mode. Call analysis and target builds are disabled. Maven POM extraction/resolution remains PARTIAL because complete transitive/test dependency coverage is not attested.

See [Architecture](docs/ARCHITECTURE.md) for scanner ownership and fallback boundaries.

## Finding Triage v0.1

Scanner results are candidates. Raw Findings are preserved, with independent TriageRecords and separate scan/triage coverage. IaC receives deterministic rule-ID classification in this version.

```text
security-check scan --mode release
security-check triage --latest
security-check triage --latest --prepare --category code --limit 20
security-check triage --latest --raw
```

Start with the current project's read-only developer task summary, without looking up a scan UUID:

```bash
security-check summary --path <project>
security-check summary --path <project> --details
security-check summary --path <project> --json
```

The default view recommends at most three follow-up tasks. Details retain every finding/advisory, review state and Raw access. The summary never scans, invokes AI, changes source/state or generates an evidence key. No history returns a first-scan suggestion. VALID means an AI review passed Runtime validation, not independent human validation or proven exploitability; recommendations never promote REVIEW to ACTIONABLE. Zero ACTIONABLE does not mean safe.

A workspace-bound MCP client can call `get_security_summary` without an ID, with `details=true` for the full list. An unbound client must supply `workspace_path`. Bounded task investigation and authorized host-agent fixes with original-scanner verification are implemented; this build's Desktop experience and independent developer usability trials remain pending.

MCP host agents use `prepare_triage` for bounded, redacted UNTRUSTED_CODE evidence, analyze it with their own model, and return structured results using `submit_triage` with the returned triage_session. `get_triage` returns coverage and grouped views. Runtime does not invoke the host model.

Configure a user-supplied OpenAI-compatible provider with `ai configure --base-url https://provider.example/v1 --model user-model --api-key-env SECURITY_RUNTIME_AI_KEY`. The key value is read only from the environment. External context requires `triage --latest --provider configured --allow-external-code-context`; absent consent fails closed. Normal scan never invokes AI. Secret values are redacted and repository content is untrusted data. Suppression requires explicit validated counterevidence; documentation/example placement or missing API search matches cannot suppress a candidate. See [Project context](docs/PROJECT_CONTEXT.md) for current limits.


Task continuation v0.1: users say “continue the first task”; the host uses that **displayed response's** continuation arguments, analyzes bounded evidence, and submits results automatically within existing authorization. Users do not provide Finding UUIDs or copy technical prompts between tools. T01 is only a display number; changed or invalid task references require a refreshed selection. Runtime does not invoke the host model. Current valid reviews are retained, cache hits do not consume new analysis slots, stale evidence is rebuilt, and failed members require an explicit retry. Discover available MCP tools at runtime; connection checks require capabilities by subset and allow additional tools.

For an authorized selected-task fix, the host calls `prepare_task_fix`, edits within its constraints, and calls `verify_task_fix` using the original task references. Runtime checks the original scanner/rule within the affected scope; finding disappearance alone does not prove functional compatibility. Runtime does not apply source patches or run target builds automatically. Actual Desktop natural-language behavior and independent developer trials remain pending.
