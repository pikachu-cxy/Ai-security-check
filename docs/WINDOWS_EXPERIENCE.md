# Windows local upgrade and security review experience

English | [简体中文](WINDOWS_EXPERIENCE.zh-CN.md)

This is a local v0.3.1 experience build with the `upgrade-and-scan-v1` contract,
not a published Release. Keep the entire
`security-check` directory; developer Python is unnecessary. Initial engine and
advisory database preparation requires network access. `version.json` records
the source commit and dirty-source flag. Compare `Get-FileHash <ZIP> -Algorithm
SHA256` with the adjacent `.sha256`. Licenses, NOTICEs and source offer remain
bundled. Compare `build_id` to distinguish different builds of the same version.
File digests verify integrity, not publisher authenticity. Old R2.2 ZIPs lack the
new inventory and cannot directly become version-slot candidates.

Release scans also support source directories extracted from ZIPs without Git.
Recognized binary documents/images/fonts are excluded with an explicit ledger;
their contents are not inspected. Oversized source, credential text and
dependency files still stop discovery with a specific diagnostic. Successful
execution does not imply comprehensive detection. First-party pack 1.2.0 includes
40 rules (32 default-on), with 5 new Java framework variants and 6 shared
JavaScript/TypeScript rules. Shared rules also select JSX/TSX files. Vue,
unmodelled frameworks and cross-function flows remain outside the demonstrated
rule scope. See [rule foundation](RULE_FOUNDATION.md) and
[target selection](SCAN_TARGET_SELECTION.md).

## Java / JS / TS experience in this build

The archive name includes `rule-foundation`. The application remains 0.3.1;
the rule pack is 1.2.0. Use `build_id` to distinguish older same-version builds.
See [rule foundation](RULE_FOUNDATION.md) for the precise API limits.
This build also fixes default Global Hook state persistence beyond Windows
legacy path limits. Internal extended path spelling targets the same files;
OS settings, logical workspace boundaries and ownership validation are unchanged.

In the disposable project from the six-step checklist, ask the Agent to create
synthetic Java NamedParameterJdbcTemplate, JavaScript child_process and
TypeScript fetch examples without executing them. Explicitly select
`$ai-security-review` to scan the entire project, report executed rules/files,
candidate risks and local evidence, and leave code unchanged for review.

Then authorize one synthetic fix, require the original rule re-scan and existing
functional tests. For Hooks, establish a safe baseline before adding a risky
edit; observe the actual advisory and safe-code re-check. A finding disappearing
does not prove application compatibility. Desktop behavior needs user acceptance.

## Install or upgrade

### One product operation for Codex

In the trusted new package's `security-check` directory, use the same command
for an initial installation or product upgrade, then prepare scanning separately:

```powershell
.\security-check.exe install codex
.\security-check.exe prepare-scanners
```

Installation configures the Runtime, global connection and Skill and inspects
caches without network preparation. `prepare-scanners` prepares pinned engine
versions and refreshes public data. Valid compatible caches are
reused; optional fallback engines remain on demand. Preparation uses the
Runtime's per-user storage and does not install dependencies or execute code
from the protected project.

Configuration and scanning readiness are separate. If tools or data cannot be
prepared, the installed configuration and previous usable cache remain, but the
preparation reports protection is not ready and returns exit code 2 (130 when cancelled).
Installation itself returns 0 after local installation succeeds; `scan_ready`
is independent. Resolve the reported problem and repeat `prepare-scanners`. Plain `setup codex` only
configures the connection and Skill; it does not download engines or establish
scanning readiness.

```powershell
.\security-check.exe install codex --offline
```

Offline installation only verifies and reuses compatible local engines, bundled
rules and unexpired vulnerability data. Missing, damaged or expired assets are
reported as incomplete preparation. The independent preparation command defaults
to a 300-second total budget, a 30-second database no-progress timeout and no
whole-download retry. Explicit retries share the budget. `prepare-scanners --status --json`
checks caches without downloads. Background periodic data updates are not
implemented. Quick dependency checks and automatic Hooks remain offline.
Successful preparation does not mean a project was scanned, a repair was
authorized or Desktop loaded its connection. Download permission and isolated
tests are not proof of actual downloads on the deployment machine. Fully quit
and restart Codex, and review Hook trust when the host asks.

### Historical manual migration and advanced steps

The `rule-foundation` package below is a historical build. Use `install codex`
above for current packages; these lower-level delivery and configuration steps
do not perform the complete product preparation operation.

The archive is `ai-security-runtime-v0.3.1-rule-foundation-windows-x64.zip`.
After extraction, open PowerShell in its **`security-check` subdirectory**, which
contains `security-check.exe` and `version.json`. If PowerShell is in the outer
extraction directory, run `Set-Location .\security-check` first:

```powershell
.\security-check.exe --version
.\security-check.exe runtime-info --json
.\security-check.exe status
```

Activate the new bundle behind a permanent launcher first. This writes only the
explicit installation directory, not Codex configuration. Keep it outside the bundle:

```powershell
$runtimeInstall = Join-Path $env:LOCALAPPDATA 'AI-Security-Runtime-install'
.\security-check.exe delivery activate --root $runtimeInstall --bundle (Get-Location).Path --json
$runtimeExe = Join-Path $runtimeInstall 'launcher/security-check.exe'
& $runtimeExe delivery status --root $runtimeInstall --json
```

Diagnose and inspect a plan before applying. Include the target project so that
project configuration overriding the global connection is checked. The plan output
must be a new file; plans expire after 15 minutes and require unchanged inputs:

```powershell
$reviewProject = 'C:\your-project'
$upgradePlan = Join-Path $env:TEMP ('runtime-upgrade-' + [guid]::NewGuid() + '.json')
& $runtimeExe upgrade diagnose --path $reviewProject --json
& $runtimeExe upgrade plan --path $reviewProject --output $upgradePlan --json
# Review paths and changes, then update the managed integration and Skill together.
& $runtimeExe upgrade apply --plan $upgradePlan --json
& $runtimeExe review-skill status
```

Unknown same-name MCP definitions require separate approval. Only after reviewing
the exact `mcp_servers.ai_security_runtime` replacement, use
`upgrade apply --plan $upgradePlan --approve-user-managed --json`. Invalid signatures,
unknown related Hooks and edited managed Skill files remain blocked; keys and user
content are not reset. `upgrade recover --json` restores an interrupted operation
only if its recorded files/keys remain unchanged by the user. The private journal
contains configuration recovery bytes: do not share it.

For another build, activate the new bundle into the same installation root, then
generate/apply a new plan through the stable launcher. `delivery rollback --root
$runtimeInstall --json` switches to the verified previous build. State and keys stay
outside version slots; rollback does not restore old authorization capabilities.
Invalid or interrupted copies are not overwritten automatically.

Fully quit and restart Desktop. In a new chat check Runtime MCP and the AI
Security Review Skill. Review/trust Hooks when the Host asks; Runtime cannot
approve them. Select the Skill or explicitly ask “Use $ai-security-review to scan
this entire project and report security risks and actual coverage.” A generic
security request may select another Skill; implicit matching has no priority guarantee.
Users do not need Finding IDs.

The Skill uses the user's `.agents/skills/ai-security-review`. The `review-skill`
actions `upgrade`, `repair`, `remove` and `status` manage that installation.
User-edited managed files produce USER_MODIFIED and remain intact, as do extra
user files and other Skills. Skill removal is independent of Runtime `uninstall`.
Host-disabled Skills require the user to enable them; installation does not.

## Isolated local trials

Choose a nonexistent directory. These CLI operations do not modify your real
configuration, Skill, state, keys, Host trust or business project:

```powershell
$runtimeTrial = Join-Path $env:TEMP ('runtime-trial-' + [guid]::NewGuid())
.\security-check.exe trial create --root $runtimeTrial --json
.\security-check.exe trial run --root $runtimeTrial -- runtime-info --json
.\security-check.exe trial run --root $runtimeTrial -- setup --scope global
.\security-check.exe trial run --root $runtimeTrial -- status --json
```

Child processes clear inherited Runtime/scanner bindings and use independent
Codex home, Skill, state, engine data and caches, offline by default. Existing
directories are not reused and trials are not automatically deleted. Missing
engines/databases are reported without silently downloading them. A CLI trial
does not establish that Desktop has loaded that isolated home. Trial setup is
Codex-only: other editors and abbreviated options are rejected before execution.
Use the full option names shown above.

## Git commit gates

Git pre-commit and Codex edit-event Hooks are separate entry points. Install explicitly:

```powershell
& $runtimeExe hooks install pre-commit --path $reviewProject --gate strict
& $runtimeExe hooks status pre-commit --path $reviewProject
& $runtimeExe hooks repair pre-commit --path $reviewProject --gate strict
& $runtimeExe hooks remove pre-commit --path $reviewProject
```

The gate scans the real Git index, not working-tree replacements, without modifying
either, including independent worktrees. Unknown Hooks are neither replaced nor
automatically chained. `strict` returns 0 for allowed, 1 for policy-blocked, and 2
for incomplete scans. `report` warns but permits incomplete scans. Ordinary `scan`
exit codes remain compatible; use `--gate strict` explicitly for gate semantics.
Staged scans support `quick` only. Removal touches only unchanged signed owned Hooks.

## Six-step experience checklist

1. **Create an isolated project.** Run this and open the unique temporary Git
   repository in Desktop. Confirm Hooks are off and MCP connects. Do not edit a
   business project or execute demonstration network requests.

   ```powershell
   $reviewDemo = Join-Path $env:TEMP ('security-review-' + [guid]::NewGuid())
   New-Item -ItemType Directory -Path $reviewDemo -ErrorAction Stop | Out-Null
   git init $reviewDemo
   New-Item -ItemType Directory -Path (Join-Path $reviewDemo '.codex') | Out-Null
   [IO.File]::WriteAllText((Join-Path $reviewDemo '.codex/config.toml'), "[features]`nhooks = false", [Text.UTF8Encoding]::new($false))
   ```
2. **Scan without Hooks.** Ask: “Only in this temporary project, create synthetic
   Java NamedParameterJdbcTemplate SQL built from a servlet request parameter,
   JavaScript inline Express request input passed to child_process.exec, and
   TypeScript inline Express request input passed to fetch. Also create a separate
   Java trust-all HttpsURLConnection hostname verifier installed on the connection
   for the existing authorization workflow. Do not execute these examples. Use
   $ai-security-review to scan all project code and show actual files, executed
   Java/JS/TS rules, local evidence and risks. Leave code unchanged.” Record scanner
   execution and FULL/PARTIAL reasons. FULL is not safety; new advisory rules do
   not grant automatic repair authorization.
3. **Review and resume.** Ask: “Use AI Security Review to investigate the first
   risk in batches without editing code,” then “Continue this task.” Expect
   redacted evidence, actionable risks and unresolved context. Sample location
   is not false-positive proof. Old scans without revision proof supply current
   context only. After reconnect, reuse valid reviews and re-prepare sessions;
   no user UUID entry should be necessary.
4. **Authorize a fix and verify.** Select the displayed TLS hostname-verifier task
   to retain the existing authorization demonstration. Ask: “Fix this TLS task and
   verify with its original scanner and rules.” Check task continuity, actual edits
   and scanner rechecks. Other Java/JS/TS candidates remain for separate review and
   explicit repair selection.
   Only SCANNER_VERIFIED_RESOLVED establishes resolution in that rule's scope;
   show INCONCLUSIVE reasons. Code changes require relevant assessments to refresh.
   Business/deployment correctness remains unknown.
5. **Observe automatic Hook feedback.** Set `hooks = true` in only the demo
   project config, fully restart Desktop, review/trust the current Hook and
   confirm it is enabled. With the repaired TLS code still safe, make a harmless
   comment edit in that file and confirm the Hook scans the baseline. Then ask:
   “For this isolated demonstration only, temporarily
   change the verifier back to always true and install it. Do not execute network
   code.” Observe automatic feedback after the edit. Remediation mode determines
   advice/confirmation/repair. For advice only, record `remediation status`, choose
   `remediation configure --mode report_only` yourself and restore your prior mode
   afterward. Missing/untrusted/invisible feedback fails; manual scanning is not
   a substitute. For the new JS/TS rules, separately exercise an explicitly selected
   synthetic file through safe → risk → safe and record advisory feedback; do not
   infer automatic repair authority from those findings.
6. **Finish and record.** Authorize repair and verify. Record coverage, findings,
   unknowns, original-rule verification and Hook feedback. Preserve observations;
   do not automatically suppress or declare safety. No publication, tag or Release
   is required. Close the demo before deciding the next product stage.

## Limits and acceptance

Runtime does not invoke an LLM for review; the Host analyzes evidence. Redaction
can hide needed semantics: retain unknowns. Workspace/link/size/encoding/revision
failures have explicit reasons. Raw findings, HUMAN quality reviews, AI triage,
coverage and fix verification remain separate. Line movement can change quality
identity; automatic semantic correlation is not implemented. The Host may send
redacted context to its chosen model.

Entire-project requests execute a new `release` scan; incremental checks use
`quick`. `scan_context` reports actual files, languages, scanner results and source
freshness. Read-only summaries do not revalidate engine/database proofs, so
`full_project_reusable` remains conservatively false. A prior Hook's FULL result
does not replace a new entire-project scan.

Automated stdio and isolated scripts verify tool paths. Natural-language Skill
selection, no-Hook Desktop review and automatic Hook visibility for this new
bundle require your six-step acceptance. Record PASS/FAIL/not verified and reasons;
previous Desktop acceptance is not inherited. Official contracts:
[Skills](https://learn.chatgpt.com/docs/build-skills), [Hooks](https://learn.chatgpt.com/docs/hooks).
