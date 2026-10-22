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

### Language coverage {#languages}

Release 0.3.9 bundles `ai-security-core 1.3.2`: **56 distinct rules, 48 enabled by default**. This is a rule subset, not complete language or framework security coverage.

| Language / files | Default-on / installed | Selected detection areas |
| --- | --- | --- |
| Java `.java` | 26 / 34 | SQL, commands, SSRF, paths / file I/O, XXE, deserialization, TLS, Servlet XSS, Spring CSRF; selected JDK, Spring, MyBatis, JPA / Hibernate, Apache APIs |
| Python `.py` | 16 / 16 | Commands, eval, SQL, SSRF, paths, pickle / YAML, TLS, Flask debug, Django CSRF / weak password hashing, HTML / templates, JWT, lxml XXE |
| JavaScript `.js` / `.jsx` | 6 / 6 | Selected Express / Node.js input flows into SQL, shells, outbound HTTP, paths, and file I/O |
| TypeScript `.ts` / `.tsx` | Shares those 6 JS rules | Execution is reported per language without counting six more distinct rules |
| MyBatis Mapper `.xml` | Counted under Java | Applicable SQL mapper patterns, not general XML coverage |
| Vue `.vue` | No corresponding default SAST rules | A scanned `.js` file does not establish coverage for `.vue` |
| Go, PHP, C / C++, C#, Ruby, Rust, and others | No bundled language-specific SAST rules | Host AI analysis is possible but does not establish scanner-rule execution |

Eight historical Java experimental rules remain disabled by default. Shared JS/TS rules count once. Counts are not accuracy or complete OWASP Top 10 claims. Framework names identify selected modeled APIs, not every version, wrapper, or cross-file call chain.

### Secrets, dependencies, and AI analysis

- **Secrets:** Gitleaks patterns apply to included text files independently of language-specific code rules. They do not guarantee recognition of every custom credential format.
- **Dependencies:** Python `requirements.txt`, `pyproject.toml`, `poetry.lock`, `Pipfile.lock`; JS/TS `package.json` and npm/Yarn/pnpm lockfiles; Java `pom.xml` and Gradle build/lock files; Go `go.mod` and `go.sum`. Actual coverage depends on engines, extracted package versions, and valid vulnerability data.
- **Other dependency ecosystems:** Composer, Cargo, Bundler, and .NET manifests are not in the current product dependency-input list. An underlying engine's broader capabilities do not establish product integration.
- **Contextual analysis:** bounded host-agent review of inputs, safeguards, and trigger conditions. Reading another language does not add SAST rules for it.

Go dependency recognition is not Go code checking. Recognized filenames do not prove a complete transitive or installed dependency graph. Dynamic, unpinned, and unresolved versions remain explicit gaps.

### Actual coverage of a check

Distinguish detected languages, available rules, selected rules, executed rules, and scanned files. File recognition, component readiness, no findings, and AI advice do not replace execution evidence. Large or binary files, unsupported types, unreadable paths, and failed engines retain their actual limitations.

Version 0.3.9 verifies Semgrep's actual execution identity and distinguishes missing engines, missing OSV databases, expired data, and unknown update times. Ready components and valid data do not establish that every project file was checked. See [preparation diagnostics](../guide/installation.md#manual-preparation).

## Monitoring and evidence

Automatic token association currently supports local Codex logs. Other hosts can use generic byte statistics; actual tokens remain unknown without an adapter. Monitoring failure does not block core functionality.

New 0.3.9 tasks preserve full sanitized long lines and fragment delivery within budgets. Missing historical preimages, unreadable source, and relevant redacted semantics remain explicit gaps.

See the [current coverage reference (Chinese)](https://github.com/pikachu-cxy/Ai-security-check/blob/feature/runtime-mvp/docs/PRODUCT_COVERAGE.zh-CN.md), [rule catalog](https://github.com/pikachu-cxy/Ai-security-check/blob/feature/runtime-mvp/src/security_runtime/rules/catalog.json), and [host engineering records (Chinese)](https://github.com/pikachu-cxy/Ai-security-check/blob/feature/runtime-mvp/docs/HOST_SUPPORT.md). The [historical rule-quality matrix](https://github.com/pikachu-cxy/Ai-security-check/blob/feature/runtime-mvp/docs/design/RULE_COVERAGE_MATRIX.md) retains sample evidence and accuracy limitations rather than the current language inventory.
