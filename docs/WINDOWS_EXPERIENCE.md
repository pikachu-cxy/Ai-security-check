# Windows local security review experience (R2.2)

English | [简体中文](WINDOWS_EXPERIENCE.zh-CN.md)

This is a local v0.3.1 experience build, not a published Release. Keep the entire
`security-check` directory; developer Python is unnecessary. Initial engine and
advisory database preparation requires network access. `version.json` records
the source commit and dirty-source flag. Compare `Get-FileHash <ZIP> -Algorithm
SHA256` with the adjacent `.sha256`. Licenses, NOTICEs and source offer remain
bundled. Extract to a permanent location; moving it requires repair.

## Install or upgrade

Open PowerShell inside the extracted directory:

```powershell
.\security-check.exe --version
.\security-check.exe runtime-info --json
.\security-check.exe status
```

For a new installation run `.\security-check.exe setup --scope global`. For an
existing installation run `.\security-check.exe repair` to use the new bundle.
Then:

```powershell
.\security-check.exe review-skill install
.\security-check.exe review-skill status
```

Fully quit and restart Desktop. In a new chat check Runtime MCP and the AI
Security Review Skill. Review/trust Hooks when the Host asks; Runtime cannot
approve them. Select the Skill or ask “Check this project's security risks.”
Users do not need Finding IDs.

The Skill uses the user's `.agents/skills/ai-security-review`. The `review-skill`
actions `upgrade`, `repair`, `remove` and `status` manage that installation.
User-edited managed files produce USER_MODIFIED and remain intact, as do extra
user files and other Skills. Skill removal is independent of Runtime `uninstall`.
Host-disabled Skills require the user to enable them; installation does not.

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
2. **Scan without Hooks.** Ask: “Only in this temporary project, create a Java
   security demonstration with a trust-all HttpsURLConnection hostname verifier,
   installed on the connection. Do not execute it. Scan and show actual coverage
   and risks.” Record scanner execution and FULL/PARTIAL reasons. FULL is not safety.
3. **Review and resume.** Ask: “Use AI Security Review to investigate the first
   risk in batches without editing code,” then “Continue this task.” Expect
   redacted evidence, actionable risks and unresolved context. Sample location
   is not false-positive proof. Old scans without revision proof supply current
   context only. After reconnect, reuse valid reviews and re-prepare sessions;
   no user UUID entry should be necessary.
4. **Authorize a fix and verify.** Ask: “Fix that task and verify with its original
   scanner and rules.” Check task continuity, actual edits and scanner rechecks.
   Only SCANNER_VERIFIED_RESOLVED establishes resolution in that rule's scope;
   show INCONCLUSIVE reasons. Code changes require relevant assessments to refresh.
   Business/deployment correctness remains unknown.
5. **Observe automatic Hook feedback.** Set `hooks = true` in only the demo
   project config, fully restart Desktop, review/trust the current Hook and
   confirm it is enabled. Ask: “For this isolated demonstration only, temporarily
   change the verifier back to always true and install it. Do not execute network
   code.” Observe automatic feedback after the edit. Remediation mode determines
   advice/confirmation/repair. For advice only, record `remediation status`, choose
   `remediation configure --mode report_only` yourself and restore your prior mode
   afterward. Missing/untrusted/invisible feedback fails; manual scanning is not
   a substitute.
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

Automated stdio and isolated scripts verify tool paths. Natural-language Skill
selection, no-Hook Desktop review and automatic Hook visibility for this new
bundle require your six-step acceptance. Record PASS/FAIL/not verified and reasons;
previous Desktop acceptance is not inherited. Official contracts:
[Skills](https://learn.chatgpt.com/docs/build-skills), [Hooks](https://learn.chatgpt.com/docs/hooks).
