# Rule Coverage Matrix — R0 synthetic baseline and R1 limits

This is historical Java foundation evidence, not the full current capability
catalog. Current source counts and acceptance status are recorded in
[development progress](DEVELOPMENT_PROGRESS.md).

The table retains the 2026-10-07 R0 synthetic baseline from the versioned
capability manifest and managed offline Scanner corpus. It is not current
real-project accuracy; R1 evidence and limitations follow below.

Current rule pack 1.2.0 adds five Java variants and six shared JS/TS advisory
rules (40 installed / 32 default-on). Existing capability maturity and the
historical R0 counts below are not expanded into a JS/TS accuracy claim.
See [current foundation and limits](RULE_FOUNDATION.md) for actual API scope;
new exact synthetic gates and per-language execution evidence are separate.

| Capability | Language | Frameworks | Rules | TP | TN | FP | FN | Maturity | Default | Auto-fix |
| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | --- | --- | --- |
| TLS hostname verification disabled | java | JDK | 1 | 4 | 2 | 0 | 0 | CORE | on | existing guarded TLS only |
| Hardcoded secret | any | scanner-owned detectors | provider-owned | 4 | 4 | 0 | 0 | CORE | on | no |
| SQL injection | java | JDBC, Spring JDBC, MyBatis | 4 | 11 | 5 | 0 | 0 | VALIDATED | on | no |
| Command injection | java | JDK | 2 | 4 | 3 | 0 | 0 | VALIDATED | on | no |
| SSRF | java | JDK, Java HttpClient, Spring RestTemplate, Spring WebFlux | 4 | 4 | 2 | 0 | 0 | VALIDATED | on | no |
| Path traversal | java | JDK | 1 | 2 | 2 | 0 | 0 | VALIDATED | on | no |
| Arbitrary file read | java | JDK | 1 | 7 | 2 | 0 | 0 | VALIDATED | on | no |
| Arbitrary file write | java | JDK | 1 | 3 | 2 | 0 | 0 | VALIDATED | on | no |
| XML external entities | java | JAXP DOM, JAXP SAX, StAX, JAXP Transformer | 4 | 6 | 4 | 0 | 0 | VALIDATED | on | no |
| Unsafe deserialization | java | JDK | 1 | 1 | 2 | 0 | 0 | VALIDATED | on | no |

**Totals: 10 capabilities; 2 CORE, 8 VALIDATED, 0 EXPERIMENTAL. 46 TP / 28 TN / 0 FP / 0 FN.**
71 synthetic cases; TP/FN and FP count occurrences, TN counts safe cases. Multiple occurrences mean TP+TN is not fixture count. Independent human ground truth: **false**. No new OSS corpus downloaded.

Java Core Pack v1 is the two CORE rows. Validated Java Pack v1 is a separate detection/guidance tier, default-on and explicitly labelled; no new automatic fixer.

## Capability → execution mapping

| Capability ID | Engine | Underlying IDs |
| --- | --- | --- |
| JAVA_TLS_HOSTNAME_VERIFICATION_DISABLED | semgrep | `ai-security.java.trust-all-hostname` |
| HARDCODED_SECRET | gitleaks | `gitleaks:*` |
| JAVA_SQL_INJECTION | semgrep | `ai-security.java.jdbc-statement`, `ai-security.java.spring-jdbc`, `ai-security.java.mybatis-annotation`, `ai-security.java.mybatis-xml` |
| JAVA_COMMAND_INJECTION | semgrep | `ai-security.java.runtime-exec`, `ai-security.java.process-builder` |
| JAVA_SSRF | semgrep | `ai-security.java.url-connection`, `ai-security.java.http-client`, `ai-security.java.spring-resttemplate`, `ai-security.java.web-client` |
| JAVA_PATH_TRAVERSAL | semgrep | `ai-security.java.file-access` |
| JAVA_ARBITRARY_FILE_READ | semgrep | `ai-security.java.arbitrary-file-read` |
| JAVA_ARBITRARY_FILE_WRITE | semgrep | `ai-security.java.arbitrary-file-write` |
| JAVA_XXE | semgrep | `ai-security.java.xxe-document-builder`, `ai-security.java.xxe-sax-parser`, `ai-security.java.xxe-stax`, `ai-security.java.xxe-transformer` |
| JAVA_UNSAFE_DESERIALIZATION | semgrep | `ai-security.java.object-deserialization` |

19 capability-owned Semgrep variants: 18 AST Java and 1 MyBatis XML. 29 total installed Semgrep rules include 8 disabled legacy Java and 2 compatible Python rules. Gitleaks detectors are not counted as one newly implemented Secret rule.

## Retained legacy execution rules

| Rule | Product maturity | Default |
| --- | --- | --- |
| `ai-security.java.jndi-lookup` | EXPERIMENTAL | off |
| `ai-security.java.ldap-search` | EXPERIMENTAL | off |
| `ai-security.java.open-redirect` | EXPERIMENTAL | off |
| `ai-security.java.security-random` | EXPERIMENTAL | off |
| `ai-security.java.trust-all-certificates` | EXPERIMENTAL | off |
| `ai-security.java.weak-cipher` | EXPERIMENTAL | off |
| `ai-security.java.weak-digest` | EXPERIMENTAL | off |
| `ai-security.java.xml-decoder` | EXPERIMENTAL | off |
| `ai-security.python.command-injection` | VALIDATED | on |
| `ai-security.python.unsafe-eval` | VALIDATED | on |

These declarations retain existing rule files without promoting them into new capabilities. Python remains compatible; unrelated Java experiments are excluded from default SAST.

## Scanner scope and observed execution

- semgrep 1.178.0: SUCCESS; 21032 ms; 42 normalized findings; target files 63; applicable rules 19; invocations 2.
- gitleaks 8.30.0: SUCCESS; 932 ms; 4 normalized findings; target files 71; applicable rules provider-owned; invocations 1.

The versioned corpus and annotated rule gate are test inputs/results under
`tests/rule_program/`. Generated local acceptance output is intentionally not
stored in `docs/`; rerun the owning acceptance scripts when fresh evidence is
needed.

## Safe cases and proof limits

SQL: PreparedStatement bindings, constants, fixed wrapper argument. Command: fixed executable with bounded arguments. SSRF: fixed endpoints and an allowlist selecting fixed URLs. Paths: normalized constant base + throwing Path.startsWith containment guard; reassignment after the guard is a risk case. XXE: hardened DOM/SAX/StAX/Transformer before parser/use; late hardening is a risk case. Deserialization: fixed trusted serialized data / non-object reads. Secrets: placeholders/examples/low-entropy fixtures/env reference without weakening provider detection.

Servlet/Jakarta and selected Spring input annotations, JDBC/Spring JDBC/MyBatis, URLConnection/HttpClient/RestTemplate/WebClient, and local wrapper propagation are bounded synthetic variants. No compiler-grade cross-file analysis, arbitrary sanitizer proof, gadget/reachability or production exploitability is claimed.

Framework applicability is enforced by typed engine patterns within an explicitly planned language/extension scope, not guessed repository framework detection. Mapper-only edits select the XML variant. Zero applicable rules skip Semgrep.

New non-Secret variants share a capability Family anchor; all applicable variants are required for absence proof. Read/write at the same sink is primary with traversal as related evidence. TLS rule bytes/identity and Secret detector families remain compatible. See [Rule Program](RULE_PROGRAM.md) for historical non-TLS identity boundaries.

## R1 independently labelled sample

Phase 1/2 evaluate the same 180 Benchmark cases (30 risky and 30 safe per group).
Counts below use upstream cases, unlike the occurrence counts in the R0 table.

| Group | Before TP/FP/FN/TN | After TP/FP/FN/TN |
| --- | --- | --- |
| SQLi | 0/1/30/29 | 1/1/29/29 |
| Command | 2/0/28/30 | 3/0/27/30 |
| Path/File | 1/5/29/25 | 1/5/29/25 |

All groups remain **INSUFFICIENT_SAMPLE**. Six confirmed FP and substantial FN
remain; no production accuracy or independent read/write recall is established.
Jeepay has no independent ground truth, and there is no real-project SSRF recall
evidence. R0 synthetic 0 FP/FN does not imply production accuracy.

Accepted fixes cover single-argument prepareCall and bounded local
ProcessBuilder.command/start. Known limitations include cross-function,
cross-file, arbitrary wrapper, builder/collection lifecycle, constant propagation
and selected framework abstractions. Cookie sources, callable overloads, array
setters and complex alias/mutation flows remain limited. Maturity is unchanged:
2 CORE, 8 VALIDATED. Versioned input labels/tests are under `tests/corpus/r1/`;
generated findings and reports stay ignored under `artifacts/r1/`.
