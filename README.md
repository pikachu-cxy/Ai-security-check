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

The intentionally vulnerable sample is in `samples/vulnerable-python`. Copy it into a temporary Git repository for a safe demo. The sample contains a synthetic token and a command injection example.

See [architecture](docs/ARCHITECTURE.md) and [extension guide](docs/EXTENDING.md).
