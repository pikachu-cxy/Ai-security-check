# Platforms and coverage

Scope: **0.3.9 Official release source and corresponding releases**. Source version, public assets, build identity, CI acceptance, and desktop validation are separate facts. Consult [downloads](../downloads.md) and each workflow's actual results.

## Platforms and editors

| Combination | Current boundary |
| --- | --- |
| Windows x64 + Codex | Native Windows bundle and CI acceptance path; Codex is the primary workflow. Synthetic host checks do not replace desktop use. |
| Windows x64 + Cursor | Full integration installs MCP, Skill, Hooks, and routine-tool permissions. Current complete desktop acceptance remains separate. |
| macOS Apple Silicon | Separate native arm64 build and acceptance; real desktop validation remains separate. |
| macOS Intel | Separate native x64 build and acceptance; ARM results do not establish Intel compatibility. |

Linux bundles are not currently distributed. Remote and multi-root workspaces are not listed as supported. Shared core behavior does not establish compatibility with every editor version, model, or platform policy.

## Managed macOS installation {#macos-installation}

[Codex](../guide/editors/codex.md#macos) and [Cursor](../guide/editors/cursor.md#macos) setup uses the separate `macos-trial-v0.3.9.3` release and dedicated Python. Both architectures have their own installation and build checks in the [macOS workflow](https://github.com/pikachu-cxy/Ai-security-check/actions/workflows/macos-trial.yml).

Isolated installation acceptance uses explicit offline component state; it does not establish that every scanner ran. Real system-policy behavior, paste warnings, editor desktop connections, and component execution need their own validation. There is no Apple Developer ID signing or notarization guarantee.

## Cursor and other clients

Cursor has full-installation commands and earlier limited Windows desktop observations, plus automated installation, MCP, and Hook checks. Current 0.3.9 desktop behavior across versions and models still needs independent acceptance. "Full integration" describes installed components, not universal compatibility.

WorkBuddy uses project-level MCP. Other clients use conditional manual stdio MCP setup. Their tool support does not imply native edit-event, approval, or recovery integration.

## Detection scope

- Code checks: installed rule subsets for Java, Python, and JavaScript/TypeScript.
- Secrets: patterns supported by installed detectors and files actually included.
- Dependencies: recognizable manifests, ecosystems, versions, and available vulnerability data.
- Contextual analysis: bounded review by the host agent of inputs, safeguards, and trigger conditions.

Recognizing an ecosystem for dependencies does not establish full SAST coverage for its language. Go and PHP are not advertised as having full code-rule coverage. Large or binary files, unsupported types, unreadable paths, and failed engines retain their actual coverage limitations. No findings is not proof of security.

Version 0.3.9 verifies Semgrep's actual execution identity and distinguishes missing engines, missing OSV databases, expired data, and unknown update times. Ready components and valid data do not establish that every project file was checked. See [preparation diagnostics](../guide/installation.md#manual-preparation).

## Monitoring and evidence

Automatic token association currently supports local Codex logs. Other hosts can use generic byte statistics; actual tokens remain unknown without an adapter. Monitoring failure does not block core functionality.

New 0.3.9 tasks preserve full sanitized long lines and fragment delivery within budgets. Missing historical preimages, unreadable source, and relevant redacted semantics remain explicit gaps.

See the [rule matrix](https://github.com/pikachu-cxy/Ai-security-check/blob/feature/runtime-mvp/docs/design/RULE_COVERAGE_MATRIX.md) and [host engineering records](https://github.com/pikachu-cxy/Ai-security-check/blob/feature/runtime-mvp/docs/HOST_SUPPORT.md), primarily in Chinese.
