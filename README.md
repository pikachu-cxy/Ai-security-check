# AI Security Runtime

The bundled `ai-security-core 1.1.0` catalog has 22 BETA Java rules and two Python
rules. Rule coverage participates in planning: no applicable rules means
`NOT_COVERED` and no Semgrep preparation or execution. Mixed Java and uncovered
JavaScript reports `CODE_SAST=PARTIAL`. See [actual rule coverage](docs/RULE_COVERAGE.md)
for the catalog, quality gate and limitations.

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

AI Security Runtime is a local-first security layer for AI coding workflows. It checks the code an AI agent writes and exposes the same security capabilities through **CLI** and **MCP**.

- **Local-first:** project source stays on your machine by default.
- **One-command setup:** native onboarding for **Cursor** and **WorkBuddy**.
- **Generic MCP:** works with other MCP-compatible coding tools such as Codex.
- **CLI:** works without any AI coding tool and is suitable for local scripts and future CI/CD use.
- **Fail clearly:** missing scanners reduce coverage instead of claiming the project is safe.

> Developer Alpha. Current checks can find security issues, but a SAFE result is not a guarantee that a project is secure.

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

The standalone Runtime includes its Python runtime. On the first scan it prepares
Semgrep in an isolated managed environment and downloads Gitleaks and Trivy as
needed. No system Python, pip or venv is required. Run inside your Git project:

```bash
security-check --version
security-check doctor
security-check scan --mode quick
security-check setup cursor
security-check setup workbuddy
```

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

Only engines selected by the scan plan are prepared. A quick scan with no changes downloads nothing; quick scans do not prepare Trivy or its database. Downloads are verified before use and do not require a system-wide PATH change.

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

- **quick** — changed and untracked files; intended for fast development feedback.
- **feature** — branch diff against main/master plus local changes.
- **release** — tracked and untracked project files for broader release review.

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

## Cursor — one-command setup

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

The Runtime manages a project-level connection in:

```text
.cursor/mcp.json
```

It preserves existing MCP servers and only manages its own `ai-security-runtime` entry.

Restart Cursor if requested.

Then ask Cursor:

> Use AI Security Runtime to scan the current Git diff. Show me the findings. If there are security issues, fix them and call verify afterwards.

A real acceptance pass means Cursor actually calls the Runtime and completes:

```text
scan_diff → finding → fix → verify → RESOLVED
```

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

## Codex and other MCP-compatible tools

Codex is currently supported through the **Generic MCP** path rather than a dedicated native installer.

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
| Codex / Generic MCP | generated MCP config allows the client to call `scan_diff` |
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

- **SAFE** — the executed checks found no policy blocker within the stated scope.
- **REVIEW** — human or agent review is recommended.
- **BLOCKED** — the current policy found a release-blocking issue.

A SAFE result is not a claim of absolute security.

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

Normal scans attempt to prepare required managed tools automatically.

Check status:

```bash
security-check tools status
```

Prepare them explicitly:

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
| Cursor native onboarding | Supported |
| WorkBuddy native onboarding | Supported |
| Generic stdio MCP | Supported |
| Codex | Generic MCP |
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

See [Trivy decoupling acceptance](docs/TRIVY_CAPABILITY_DECOUPLING.md) and [OSV fallback acceptance](docs/OSV_DEPENDENCY_FALLBACK.md).

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

A workspace-bound MCP client can call `get_security_summary` without an ID, with `details=true` for the full list. An unbound client must supply `workspace_path`. Continued investigation and repair remain Planned; the three independent developer usability trials are still pending.

MCP host agents use `prepare_triage` for bounded, redacted UNTRUSTED_CODE evidence, analyze it with their own model, and return structured results using `submit_triage` with the returned triage_session. `get_triage` returns coverage and grouped views. Runtime does not invoke the host model.

Configure a user-supplied OpenAI-compatible provider with `ai configure --base-url https://provider.example/v1 --model user-model --api-key-env SECURITY_RUNTIME_AI_KEY`. The key value is read only from the environment. External context requires `triage --latest --provider configured --allow-external-code-context`; absent consent fails closed. Normal scan never invokes AI. Secret values are redacted and repository content is untrusted data. Suppression requires explicit validated counterevidence; documentation/example placement or missing API search matches cannot suppress a candidate. See [acceptance and limits](docs/AI_TRIAGE_ACCEPTANCE.md).


继续核查 v0.1：MCP 当前11个工具，新增 `prepare_task_triage`。用户看到汇总后说“继续第一项”，宿主使用**实际展示响应**中该项的 `continuation.arguments`，不能把 T01 当稳定身份或重新取第一项。得到受限 packet 后沿 `submit_triage` 提交，Runtime 不调用宿主模型。有效审阅保留，缓存不占新分析名额，STALE 重建、FAILED 仅 `retry_failed=true` 显式重试。任务变化/引用无效要求刷新重新选择；不存在自动补丁或目标构建。三位真实开发者试用仍待验收。
