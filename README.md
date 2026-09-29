# AI Security Runtime

Security runtime for AI coding agents.

Repository: https://github.com/pikachu-cxy/Ai-security-check

## 项目声明

AI Security Runtime 是独立的本地安全检查工具，供 AI Coding Agent 和开发者通过 CLI、MCP 或 Git Hook 调用。默认在本机扫描 Git 项目，不上传完整源码。扫描结果用于帮助发现和复核风险，不代表对项目安全性的绝对保证。`samples/vulnerable-python` 中的漏洞和密钥字符串均为演示用途，请勿用于生产环境。

Agent writes. Security Runtime verifies. The first release scans a local Git repository without uploading its source. It uses local Semgrep, Gitleaks, and Trivy executables when available. Missing scanners are reported and do not prevent the others from running.

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

Install [Semgrep](https://semgrep.dev/docs/getting-started/quickstart), [Gitleaks](https://github.com/gitleaks/gitleaks), and [Trivy](https://trivy.dev/latest/getting-started/installation/) separately. `doctor` shows availability. The CLI itself works without an AI API key.

Trivy needs a local vulnerability database before its first offline scan. Prepare it once with `trivy image --download-db-only`; this downloads scanner data and does not send project source. If a scanner or its data is unavailable, the scan reports `PARTIAL` and `REVIEW` rather than claiming the project is safe.

```bash
security-check scan --mode quick --path .
security-check scan --mode feature --json
security-check scan --mode release
security-check hooks install pre-commit
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
