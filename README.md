# AI Security Runtime

Security runtime for AI coding agents.

Repository: https://github.com/pikachu-cxy/Ai-security-check

## 项目声明

AI Security Runtime 是独立的本地安全检查工具，供 AI Coding Agent 和开发者通过 CLI、MCP 或 Git Hook 调用。默认在本机扫描 Git 项目，不上传完整源码。扫描结果用于帮助发现和复核风险，不代表对项目安全性的绝对保证。`samples/vulnerable-python` 中的漏洞和密钥字符串均为演示用途，请勿用于生产环境。

Agent writes. Security Runtime verifies. The first release scans a local Git repository without uploading its source. Semgrep is installed with the Python package. Gitleaks and Trivy are prepared automatically on first use. Missing scanners are reported and do not prevent the others from running.

## Install

Python 3.12 or newer is required.

```bash
git clone https://github.com/pikachu-cxy/Ai-security-check.git
cd Ai-security-check
python -m venv .venv
pip install -e '.[mcp]'
security-check doctor
security-check doctor --json
security-check scan
security-check mcp
```

The CLI itself works without an AI API key. `security-check scan` prepares pinned scanner versions and the Trivy vulnerability database automatically. The first run needs internet access; later scans can use managed copies offline. Official release assets are downloaded over HTTPS and checked against pinned SHA256 digests before execution. No system installation or PATH change is needed.

The Trivy database download does not send project source. If a scanner or its data is unavailable, the scan reports `PARTIAL` and `REVIEW` rather than claiming the project is safe.

```bash
security-check scan --mode quick --path .
security-check scan --mode feature --json
security-check scan --mode release
security-check hooks install pre-commit
security-check tools status
security-check tools install --all
security-check doctor --verbose
security-check licenses
security-check licenses --check-distribution
```

Quick scans changed and untracked files, or staged files in the pre-commit hook. Feature scans the branch diff against main/master plus local changes. Release scans the tracked and untracked project files. `--json` returns a stable machine-readable scan result and a nonzero exit code for `BLOCKED`. A missing scanner produces a partial result, never a false claim of safety.

## Agent integrations

```text
Codex / Cursor / Claude Code / WorkBuddy
                │
       MCP (local stdio) or Hook
                │
          Security Runtime
                │
    local scanner executables
```

Configure an agent MCP client to launch `security-check mcp` in the project directory. Available tools: `scan_diff`, `scan_project`, `get_findings`, `generate_fix`, `verify`. `generate_fix` returns a coding task and never edits source.

The MCP tools `scan_diff` and `scan_project` accept an optional `workspace_path`. An explicit path takes priority; otherwise the server locates the Git root above its startup directory. The old `path` argument remains accepted for existing clients. Paths that resolve to the user Home, a drive root, or a Windows system directory are rejected. The same workspace resolver is used by the CLI and pre-commit hook.

`doctor` locates the Git root by default. Outside a Git repository it returns immediately with a project hint. An explicit `--path` may inspect a non-Git project directory. `doctor --json` returns a stable machine-readable environment, workspace, scanner plan, and status. Missing scanners limit scan coverage without disabling the Runtime. Scan results include `coverage` (`FULL`, `PARTIAL`, or `MINIMAL`); incomplete scans do not claim the project is safe.

Discovery skips generated and dependency directories and stops at bounded file, directory, depth, and file-size limits. Adjust them with `SECURITY_RUNTIME_MAX_FILES`, `SECURITY_RUNTIME_MAX_DIRECTORIES`, `SECURITY_RUNTIME_MAX_DEPTH`, `SECURITY_RUNTIME_MAX_FILE_SIZE`, and the comma-separated `SECURITY_RUNTIME_EXCLUDE_DIRS` when needed. MCP logs use stderr and default to `WARNING`; set `SECURITY_RUNTIME_LOG_LEVEL` to `ERROR`, `WARNING`, `INFO`, or `DEBUG`. Scan history uses a user-level state directory (Windows `%LOCALAPPDATA%\AI Security Runtime`); override it with `SECURITY_RUNTIME_STATE_DIR`.

The intentionally vulnerable sample is in `samples/vulnerable-python`. Copy it into a temporary Git repository for a safe demo. The sample contains a synthetic token and a command injection example.

See [architecture](docs/ARCHITECTURE.md) and [extension guide](docs/EXTENDING.md).

## Managed tools

`security-check tools status` reports each engine and the Trivy database. `security-check tools install gitleaks`, `security-check tools install trivy`, and `security-check tools install --all` prepare them explicitly for troubleshooting. Windows stores managed tools in `%LOCALAPPDATA%\AI-Security-Runtime`; set `SECURITY_RUNTIME_DATA_DIR` to change that location. `SECURITY_RUNTIME_OFFLINE=1` prevents new downloads. Enterprises may set `SECURITY_RUNTIME_GITLEAKS_PATH` or `SECURITY_RUNTIME_TRIVY_PATH`, or use `[tools.gitleaks] path = "..."` in the data directory's `config.toml`. An explicit path must point to the pinned compatible version.

## Rule and license boundaries

Semgrep is an independently installed subprocess engine. Default scans use only the versioned, local `ai-security-core` first-party rule pack. They do not fetch Semgrep community or registry rules. `security-check scan --rules <directory>` runs user-provided local rules without copying or redistributing them. Engine licenses and rule-pack licenses are tracked separately. See [third-party notices](THIRD_PARTY_NOTICES.md) and [extension guide](docs/EXTENDING.md).
