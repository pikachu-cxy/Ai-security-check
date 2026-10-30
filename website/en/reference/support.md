# Support and detection coverage

This page describes **0.3.11**. [Downloads](../downloads.md) include the release artifacts, checksums, source manifest, and acceptance evidence.

## Platforms and editors

| Platform / editor | Delivery and scope |
| --- | --- |
| Windows x64 | Native bundle with focused Windows regression and package acceptance |
| macOS Apple Silicon / Intel | Separately built and verified native bundles; managed Python installation is also available |
| Codex / Cursor | User-level MCP, Skill, and Hooks through `install codex` / `install cursor`; routine Cursor tool allowlist |
| WorkBuddy | Project-level MCP; no promise of automatic edit observation |
| Other clients | Manual local stdio MCP setup according to the client's supported format |

No Linux full bundle is published. Use the actual local project root. Remote, multi-root, model, desktop-version, and enterprise-policy combinations require their own verification; CI acceptance does not establish them all.

## macOS installation {#macos-installation}

[Codex](../guide/editors/codex.md#macos) and [Cursor](../guide/editors/cursor.md#macos) offer an architecture-aware installer with dedicated Python and verified downloads. It pins the public `macos-trial-v0.3.11` release. Native bundles use `v0.3.11`. These share a version number but have different build identities; compare each with its own source and checksum.

See the [managed installation workflow](https://github.com/pikachu-cxy/Ai-security-check/actions/workflows/macos-trial.yml) for both architectures. Real desktop integration, first-download policy, and actual scanner readiness remain separately verifiable. There is no Apple Developer ID signing or notarization guarantee.

## Cursor integration and reconnects

Full installation includes an exact routine-tool allowlist. Run confirmations still depend on Cursor mode, local-user configuration, and team policy. Tool execution permission does not authorize a product risk fix.

Hooks provide signed chat ownership. Reconnect acceptance reads the original check and saved dispositions without rescanning. Agents must not invent credentials. Configuration in one operating-system user's directory does not automatically transfer to another account. See [Cursor setup](../guide/editors/cursor.md).

## Languages {#languages}

**OpenGrep with the installed `opengrep-rules` pack is the default code scanner.** Pack identity, selected rules, and actual execution are tracked separately.

| Input | Coverage interpretation |
| --- | --- |
| Java, Python, JavaScript/TypeScript, Go, PHP | Applicable rules selected by file type and installed pack; execution reported per scan |
| C/C++, C#, Ruby, Rust, Kotlin, Shell, YAML, and other recognized types | Recognition and rule selection do not prove a matching rule or successful parser execution |
| Vue | Supported JS/TS script blocks; templates, styles, and external scripts are not covered |
| Native Java/Python dataflow | Bounded propagation and calls; loops, dynamic arguments, context, and budgets can limit coverage |
| Native Go SQL and JS/TS dynamic-code checks | Additional modeled candidates, not whole-program proofs |

Available, selected, and executed rules and files are separate measures. Unsupported semantics, exclusions, and parser failures remain visible. Language support does not imply complete framework or vulnerability coverage.

## Secrets, dependencies, and configuration

Gitleaks checks selected text for supported credential patterns. Trivy performs default dependency vulnerability checks and applicable configuration checks. Dependency inputs include recognized Python, npm/Yarn/pnpm, Maven/Gradle, and Go manifests or lockfiles; underlying engine support alone does not establish product support for every ecosystem.

OSV and Semgrep remain available for compatibility or explicit use. They are not required default providers, and Trivy failure does not automatically fall back to OSV. No applicable manifest may mean not applicable; unavailable tools or data for applicable inputs mean a gap.

## Task scope

Default development checks scan recorded files without a project-wide baseline. Related business-logic reading belongs to agent review and does not expand scan scope. Request whole-project scans or strict before/after audits explicitly.

Saved reads do not revalidate disk contents. Distinguish missing files, scanner limitations, and observation notes. Unrelated files outside this task do not require a whole-project scan to complete a recorded-file check.

## Statistics and monitoring

[Risk statistics](../guide/risk-handling.md) read the current local user's Codex and Cursor records, separately or together. Cross-editor entries retain their identities; this first stage does not deduplicate them or sync across devices.

[Usage monitoring](../guide/context-cost.md) is optional. Automatic current-chat token association uses supported Codex local logs; missing usage adapters remain unknown.
