# Java / JavaScript / TypeScript rule foundation

This document preserves the earlier Java foundation milestone and its evidence.
Its release counts are historical; current catalog counts and acceptance status
are recorded in the source repository's
[development progress](https://github.com/pikachu-cxy/Ai-security-check/blob/feature/runtime-mvp/docs/DEVELOPMENT_PROGRESS.md).

This is a local experience milestone, not a Release or production-accuracy
claim. Runtime application version remains 0.3.1. The independent
`ai-security-core` rule pack is 1.2.0 and Rule Program mapping is 1.1.0.

## What changed

There are 40 installed execution rules: 32 Java, six shared JavaScript/TypeScript,
and two existing Python rules. Eight legacy Java experiments remain default-off;
32 execution rules are default-on. The six shared rules are six identities, not
twelve: TypeScript and JavaScript file execution are reported separately.

| Language / API | Added detection |
| --- | --- |
| Java Spring NamedParameterJdbcTemplate | Untrusted SQL template, separate from bound parameter values |
| Java JPA / Hibernate | Dynamic query/native SQL construction, separate from setParameter values |
| Java Apache Commons Exec | Input-selected command reaches execute; ordinary fixed-tool arguments are separate |
| Java Apache HttpClient 4/5 classic | Input-selected request URL reaches an HTTP execution boundary |
| Java Spring MultipartFile | Client filename/request input reaches the upload destination |
| JS/TS pg, mysql, mysql2 | Request input reaches SQL text, including documented query options |
| JS/TS child_process | Shell command/argv input, explicit POSIX and Windows shell execution |
| JS/TS fetch, axios, http/https | Request-controlled outbound URL/host |
| JS/TS fs and response file APIs | Request-controlled read, write, deletion or file response path |

All eleven new rules and their test inputs are independently authored
Apache-2.0 FIRST_PARTY definitions. No restricted external rule or fixture was
imported. See [source review](RULE_SOURCE_INVENTORY.md) and per-rule provenance.
Unchanged rules keep their exact original YAML and 1.1.0 rule versions; adding
rules does not rewrite their patterns. Catalog/rule versions still cross-check,
and scanner/fix verification binds pack checksum, pack version and rule version.

## Quality and authorization

The existing ten capability IDs, two CORE/eight VALIDATED maturity declarations,
family anchors and automatic-fix eligibility are unchanged. The five Java
variants join the appropriate existing family. The six JS/TS rules use the
existing enabled advisory execution-entry mechanism, like Python; they do not
inherit Java capability maturity or its earlier quality evidence. Their source
metadata is BETA/MEDIUM. The existing mapping term VALIDATED enables
detection/guidance after fixture gates, not a real-project precision claim.

Raw scanner findings, human quality reviews, AI triage, coverage and fix proof
remain separate. A synthetic positive/negative gate establishes only behavior
on those authored inputs. It does not establish production precision or recall.
Findings need context review; files under tests/samples are not automatically
false positives or suppressed. These additions authorize no automatic edits.

## Scope and limits

Java input modeling uses explicit servlet types and selected Spring annotations.
JS/TS input modeling covers selected inline HTTP-handler shapes, CJS/ESM imports,
typed callbacks and documented API positions. Named independent controllers,
cross-function/file wrappers, ORM abstractions and arbitrary mutable options are
not proven. This is not all Java/JS/TS security or complete OWASP Top 10 coverage.

Apache HTTP modeling is bounded to classic HttpGet/HttpPost request flows.
Async methods, other HTTP verbs, arbitrary builder/lifecycle aliases and
executeOpen are not claimed. Commons Exec detects externally selected commands,
not every argument-specific injection in a fixed tool. Path containment checks
are lexical, not filesystem/symlink safety proofs. The JS/TS rule set does not
prove redirect/DNS/network policies or arbitrary sanitizer behavior.

.js/.jsx/.ts/.tsx use applicable shared rules. Annotated fixtures exercise both
source parsers and JSX/TSX parsing. Vue single-file components are not added;
an uncovered .vue beside a covered .js keeps coverage partial. Unsupported
languages, parser failures, engine skips/timeouts and unexecuted rules remain
visible. FULL means execution of the declared scope/contracts, not absence of
all vulnerabilities.

Module-specific .mjs/.cjs/.mts/.cts extensions are not included in this build's
SAST language selection. A neighboring .js/.ts execution result does not cover
them. Adding their parser/selection proof is a separate follow-up.

## Hook and user testing

Hooks still use the existing bounded file scope, language selection and fresh
scanner evidence. A scan is not expanded to every project file for an edit.
There is no new asynchronous queue, deep graph engine or special Quick rule
profile in this milestone. Rule growth can increase matching/startup time;
the isolated acceptance report measures actual local edit/scan/re-scan paths.
No timing guarantee is inferred from the rule count.

Hook absence proof retains the original detector-ID/version receipts within a
capability family, including families with both 1.1.0 and 1.2.0 variants. It still
requires the same pack/engine and execution of every applicable family rule on
the file with no error or skip. Legacy snapshots with no detector receipt cannot
prove absence for a mixed-version family by guessing its first rule. A fresh
scan supplies the new receipts; a Hook family disappearing is not an Episode
CLOSED decision or a functional compatibility proof.

Windows Hook state uses extended filesystem path spelling internally, including
atomic replacement, reads and session restart. Logical workspace/state directory
boundaries, full SHA256 names, link rejection and signed receipts remain unchanged.
This also supports the default nested Global state layout under Windows legacy
path limits; no operating-system setting is changed.

Follow [Windows Chinese instructions](WINDOWS_EXPERIENCE.zh-CN.md) or
[English instructions](WINDOWS_EXPERIENCE.md) to activate/diagnose/plan/apply a
local package. Do not overwrite Codex config by hand. Existing modified user
configuration and Skill files remain subject to ownership/upgrade checks.

Six-step Desktop checklist:

1. Verify the ZIP SHA256, runtime-info build identity and rule pack version.
2. Upgrade using the documented delivery/upgrade flow; restart Codex Desktop.
3. In a temporary test project, ask the AI Security Review Skill to scan all
   project code; check selected/executed Java/JS/TS rule IDs and exclusions.
4. Ask for per-finding local evidence and triage; distinguish candidates from
   verified risks and keep uncertainty visible.
5. Authorize one synthetic issue fix, then require the original scanner/rule
   re-scan and available functional tests; a script's safe replacement is not
   proof of the Desktop fix workflow or application compatibility.
6. Establish a safe Hook baseline in that temporary project, ask the agent to
   edit it to a synthetic risky API use, and inspect the actual automatic
   advisory/task. Restore the safe code and inspect the scanner re-check.

Do not insert demonstrations into business code, launch vulnerable services,
or share real findings/source/secrets as test fixtures. Scripted CLI/MCP/Hook
acceptance is not a substitute for the user's actual Desktop experience.

## Developer verification

The final full pytest collection covered 2,159 cases in 92 modules, partitioned
into three disjoint groups without removing cases: 2,109 passed, 24 skipped,
26 existing strict expected failures, and no unexpected failures or XPASS.
Six additional subtests passed. Skips comprise thirteen unavailable symlink
fixtures, six legacy PATH-based real-engine checks, three opt-in performance
benchmarks, one non-Windows behavior and one Windows filename limitation.
Real managed-engine execution is independently exercised below; skipped tests
are not counted as passes. Distribution/doctor focused checks, compliance and
isolated installed-wheel integrity also passed.

The local whole-pack Semgrep gate observed 158 annotated risky cases and 127
annotated safe cases, with no missing/unexpected matches or engine errors across
40 rules. These are synthetic behavior checks, not real-project TP/FP estimates.
An isolated 36-scan quick/Hook/re-scan run was FULL throughout and observed two
`safe → risk → safe` cycles per language. Each Hook cycle recorded one new and
one resolved candidate, without declaring an Episode CLOSED.

The extracted Windows bundle also passed four official-SDK MCP scans: release
and quick found three synthetic candidates, then release and quick found none
after safe replacement. All 29 applicable rule identities executed on three
files (Java 23, JavaScript 6, TypeScript 6); the six shared identities are counted
once in the total. Three requested finding details supplied original EXACT
local evidence. This does not verify the Desktop conversation or application
functionality.

On this machine with prepared engines, six observations per language gave Hook
median latencies of 4.314 s (Java), 4.286 s (JS) and 4.597 s (TS); p95 was
4.558 s, 4.507 s and 4.757 s respectively. Quick cold-start outliers reached
11.761 s. These are local observations, not a neutral benchmark or speed promise.

`scripts/test_rules.py` validates the whole local pack and exact risky/safe
annotations, including explicitly registered TypeScript/JSX/TSX companions.
`tests/test_shared_rule_languages.py` checks shared identity and language/file
proof, partial .vue coverage and independent version validation. Existing Rule
Program corpus and strict expected limitations continue to run.

`scripts/rule_foundation_acceptance.py --output <local-only.json>` produces
actual isolated scan/Hook/re-scan counts and latency evidence; it does not run
an LLM or mutate real host configuration. Generated reports belong under
ignored `.tools`/`dist`, not in source control. Installed wheel integrity and
the native Windows artifact verifier check packaged rules and existing host
contracts. Desktop natural-language/Hook visibility remains user acceptance.

`scripts/rule_foundation_mcp_acceptance.py` uses the official MCP stdio SDK against
an extracted native executable, isolated state/home and prepared offline engines.
It exercises the public `scan_project` release and `scan_diff` quick contracts,
bounded per-finding evidence and original-rule absence after safe synthetic
replacement. It does not execute the synthetic application or replace Desktop
acceptance.

From the repository root with the development environment installed:

```powershell
.\.venv\Scripts\python.exe scripts\test_rules.py
.\.venv\Scripts\python.exe scripts\rule_foundation_acceptance.py --output .tools\rule-foundation-acceptance.json
# Point to a fresh extraction of the verified native ZIP and its prepared data.
$nativeExe = 'C:\your-temp-extraction\security-check\security-check.exe'
$managedData = 'C:\your-isolated-verified-data'
.\.venv\Scripts\python.exe scripts\rule_foundation_mcp_acceptance.py --executable $nativeExe --data-dir $managedData --output .tools\rule-foundation-native-mcp.json
```

The native SDK command reuses engines prepared by the full artifact verifier;
it does not replace fresh first-install verification. All generated acceptance
reports stay local and are excluded from source commits.

Windows artifact and SDK verification exclude developer `python`, `python3`
and `py` from the child PATH and remove PYTHONPATH/PYTHONHOME. A fresh extracted
bundle runs from a temporary workspace with isolated state and Codex home;
the full artifact gate prepares CPython/Semgrep from an empty managed data root
and checks the second preparation reuses the installation. Per-archive SHA256,
source commit and verification sidecars identify the actual tested build.
