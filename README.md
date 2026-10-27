# AI Security Runtime

English | [简体中文](README.zh-CN.md)

Security checks, contextual review, and traceable fix verification for AI coding workflows.

AI Security Runtime checks the changes made during a development task, combines scanner results with your host agent's review of relevant code, and explains concrete risks, existing safeguards, and unknowns. You choose whether to fix, defer, or exclude a finding. The agent makes authorized changes; the Runtime retains the original finding and verification evidence.

Current development source defaults to **lightweight AI edit checks**. Hooks only record observed file paths; they do not start scanners. Finishing the coding task schedules one combined background check, then the host agent reviews findings and security-relevant changes. No whole-project baseline or workspace snapshot is created for ordinary development. Scanner inputs remain fixed for the selected files, and results retain their actual version and coverage gaps. Later edits remain pending until the next explicit finish. Unknown edit scope never silently expands to a project scan. Explicit full-difference audits, existing strict tasks, and native finding repairs keep their original contracts. Published packages follow their actual build identity; see the [development design](docs/LIGHTWEIGHT_DEVELOPMENT_CHECK.zh-CN.md).

**Current source: 0.3.9 / Official release.** The development branch is `feature/runtime-mvp`. Native bundles and the managed macOS installer have separate release records; available downloads, checksums, and build identities are listed in the [installation guide](https://pikachu-cxy.github.io/Ai-security-check/en/downloads.html). Codex is the primary validation host. Current Cursor and macOS desktop workflows still require independent validation; see [support boundaries](https://pikachu-cxy.github.io/Ai-security-check/en/reference/support.html).

The current development source supports asking **“Open risk statistics”** to view locally retained project risks. The dashboard is read-only; it does not start scans or change dispositions. Historical records may contain duplicates or lack a current disposition. Availability in published packages depends on their actual build.

## Documentation

[English documentation](https://pikachu-cxy.github.io/Ai-security-check/en/) · [中文文档](https://pikachu-cxy.github.io/Ai-security-check/)

The [English quick start is also available in this repository](website/en/guide/quickstart.md). Website publication waits for the documented installation packages to be public.

- [Overview](website/en/guide/overview.md) · [Quick start](website/en/guide/quickstart.md) · [Downloads](website/en/downloads.md)
- [Codex setup](website/en/guide/editors/codex.md) · [Cursor setup](website/en/guide/editors/cursor.md) · [Manual MCP](website/en/guide/mcp.md)
- [Daily workflow](website/en/guide/workflow.md) · [Handle findings](website/en/guide/risk-handling.md) · [First demo](website/en/guide/demo.md)
- [Usage monitoring](website/en/guide/context-cost.md) · [Privacy](website/en/reference/privacy.md) · [Troubleshooting](website/en/reference/faq.md)

The documentation site uses VitePress and GitHub Pages. Its source is in `website/`; engineering contracts and acceptance records remain in `docs/`, primarily in Chinese.

## What it does

1. **Record observed edits.** Track the files involved in AI coding without first inventorying the project or requiring a Git commit.
2. **Check at task completion.** Combine recorded edits into one bounded background scan, then review findings and relevant safeguards. Unobserved changes remain a coverage limitation.
3. **Explain the evidence.** Keep file locations, potential impact, existing protections, and unverified assumptions visible.
4. **Let the user decide.** A request for impact analysis remains read-only. Fixing a selected issue requires authorization; deferral and exclusion retain their own records.
5. **Verify the original finding.** A new task with zero findings, ordinary passing tests, or an exclusion does not prove an earlier issue was fixed.

Full integration includes **Runtime + MCP + companion Skill + Hooks**. [MCP-only setup](website/en/guide/mcp.md) is available when you manage orchestration yourself. Ordinary chat, read-only requests, and unchanged tasks should not trigger a project scan.

## Install

Version 0.3.9 is the official release for Windows x64, Mac Apple Silicon (M series), and Mac Intel. The release pipeline publishes these downloads only after regression, compliance, package-integrity, and all three native acceptance gates pass:

| Platform | Bundle |
| --- | --- |
| Windows x64 | [ai-security-runtime-v0.3.9-windows-x64.zip](https://github.com/pikachu-cxy/Ai-security-check/releases/download/v0.3.9/ai-security-runtime-v0.3.9-windows-x64.zip) |
| Mac Apple Silicon | [ai-security-runtime-v0.3.9-macos-arm64.tar.gz](https://github.com/pikachu-cxy/Ai-security-check/releases/download/v0.3.9/ai-security-runtime-v0.3.9-macos-arm64.tar.gz) |
| Mac Intel | [ai-security-runtime-v0.3.9-macos-x64.tar.gz](https://github.com/pikachu-cxy/Ai-security-check/releases/download/v0.3.9/ai-security-runtime-v0.3.9-macos-x64.tar.gz) |

### Windows x64

Download the full bundle and its matching SHA256 file from the [downloads page](https://pikachu-cxy.github.io/Ai-security-check/en/downloads.html). Verify and extract the complete archive. In PowerShell, from the directory containing the `security-check` folder, run **one** command for your editor:

```powershell
# Codex
.\security-check\security-check.exe install codex

# Or Cursor
.\security-check\security-check.exe install cursor
```

The full bundle includes Python; no separate Python, pip, Node.js, or virtual environment is required. Keep the entire folder. Installation starts preparing scanner components; initial downloads may continue in the background.

### macOS: Apple Silicon or Intel

For the official full bundle, download the matching archive above, verify its `.sha256`, extract it, and run `./security-check/security-check install codex` (or `install cursor`) from the extraction directory. The commands below remain a separate optional managed-installation trial.

Choose **one** command for your editor:

```sh
# Codex
curl --proto '=https' --tlsv1.2 -fsSL https://pikachu-cxy.github.io/Ai-security-check/install/macos.sh | bash -s -- codex

# Or Cursor
curl --proto '=https' --tlsv1.2 -fsSL https://pikachu-cxy.github.io/Ai-security-check/install/macos.sh | bash -s -- cursor
```

[Inspect the installer](https://pikachu-cxy.github.io/Ai-security-check/install/macos.sh) before running it. This managed installation uses the separate `macos-trial-v0.3.10` release, detects your architecture, and prepares a dedicated Python environment. It does not require preinstalled Python, Git, or Homebrew. Keep `~/.local/share/AI-Security-Runtime-macos-trial`; an existing connection for the selected editor may be updated.

Apple Developer ID signing, notarization, and real desktop compatibility are separate validation items. If macOS blocks pasting or launching, read the [troubleshooting guide](website/en/reference/faq.md#macos-paste) and retain the exact message.

### Restart and verify

Completely quit and reopen the editor after installation. In a new chat in the intended local project, ask:

> Use actual AI Security Runtime tool calls to check the connection, version, build_id, source commit, scanner readiness, vulnerability data, and bound project path. Confirm companion guidance is available. Do not scan or modify the project. Explain any missing information.

Matching version numbers do not guarantee matching builds. Installation, component preparation, a working editor connection, and a completed project check are separate facts. See [verification](website/en/guide/verify.md), then try the [isolated demo](website/en/guide/demo.md).

## Source version 0.3.9

- One-step monitoring for the current Codex chat, with verified local session matching and HTML/JSON report export. Manual log selection is not required for this flow.
- Separate reporting of chat tokens, observation time, and associated tool duration. Token use cannot reliably be split into development-only and security-only portions; unsupported measurements remain unknown.
- Optional monitoring that can stop, fail, or be omitted from a source distribution without changing core scans, task review, or fix authorization. Keep managed installation packages intact.
- Original source evidence for new tasks, including embedded credentials, with long lines fragmented to fit response budgets. Historical evidence already lost by older tasks is not reconstructed.
- Existing guidance deduplication, compact summaries, explicit file scopes, and verified scan-result reuse. Reuse does not replace required review or authorize a fix.

See the [changelog](website/en/reference/changelog.md) and [release workflow](https://github.com/pikachu-cxy/Ai-security-check/actions/workflows/release.yml). A source commit or candidate build is not proof that a native bundle has been published.

## Coverage and data handling

Current source uses **OpenGrep 1.32.0** with **opengrep-rules**, pinned to commit `f1d2b562b414783763fd02a6ed2736eaed622efa`. The bundled directory contains 1,934 upstream YAML files and 2,007 rules. Execution selects applicable local rules; custom rule directories remain supported. The previous first-party YAML pack is no longer bundled. Historical Semgrep results remain readable.

Rules include multiple languages and frameworks; inventory counts do not prove complete coverage or detection accuracy. Actual executed rules, scanned paths and parser errors determine each result. Gitleaks checks secrets and Trivy checks supported dependency inputs independently.

See the [language and detection matrix](website/en/reference/support.md#languages) and [current source evidence (Chinese)](docs/PRODUCT_COVERAGE.zh-CN.md). Engines, data, actual file scope, and contextual review determine each result; no findings is not proof of security.

The Runtime and scanners run locally. Semantic analysis is performed by the host agent, whose own model service and account policies govern its data handling. Local task records may contain code snapshots. Component preparation and vulnerability data can require network access. See [coverage](website/en/reference/support.md) and [privacy](website/en/reference/privacy.md).

## Develop from source

Requires Python 3.12+ and Git. Keep the checkout in a stable directory. This development installation is separate from a published bundle:

```sh
git clone --branch feature/runtime-mvp https://github.com/pikachu-cxy/Ai-security-check.git
cd Ai-security-check
python3 -m venv .venv
.venv/bin/python -m pip install -e .
.venv/bin/security-check install codex --dev
```

On Windows, use `py -3.12 -m venv .venv`, `.\.venv\Scripts\python.exe`, and `.\.venv\Scripts\security-check.exe` instead. Pulling source does not automatically update an installed Runtime. Restart the host and verify its actual build after changing the installation.

For the documentation site:

```sh
cd website
npm ci
npm run docs:dev
# Production build, including internal link checks:
npm run docs:build
```

Node.js is a documentation-development dependency, not a bundled Runtime requirement. See [documentation maintenance](website/en/contributing/deployment.md).

## Licensing and support

AI Security Runtime uses a **closed-core, open-ecosystem** licensing model. The Runtime Core is proprietary. Explicitly marked components, the public scanner/plugin extension contract, are Apache-2.0 licensed. The bundled upstream rules retain LGPL-2.1 and Commons Clause terms. Third-party engines and dependencies retain their own licenses. A public repository does not make the entire Runtime open source.

Read [LICENSE](LICENSE), [licensing](LICENSING.md), [EULA](EULA.md), [third-party notices](THIRD_PARTY_NOTICES.md), and [source offer](SOURCE_OFFER.md) for the applicable terms.

Report issues through [GitHub Issues](https://github.com/pikachu-cxy/Ai-security-check/issues) with your OS, architecture, editor version, actual build identity, reproduction steps, and sanitized diagnostics. Do not commit credentials, raw chats, private source snapshots, scanner databases, or local runtime state.
