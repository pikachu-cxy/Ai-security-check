# Rule Program v1

Rule Program v1 is capability-first. It maps:

`Capability → underlying scanner rules → Finding Family / Episode → Policy → remediation / proof`

The product identity is the capability manifest at
[`src/security_runtime/rules/capabilities.json`](../src/security_runtime/rules/capabilities.json).
Catalog and YAML files are execution definitions, not the product quality measure.

The current local foundation release is rule pack 1.2.0 / mapping 1.1.0:
40 installed rules, five new Java variants and six shared JS/TS advisory rules,
32 default-on. Capability count/maturity remain unchanged. The counts/evidence
below retain the earlier R0/R1 baseline. New behavior, scope and synthetic
limitations are documented in [RULE_FOUNDATION.md](RULE_FOUNDATION.md).

## Current capabilities

| Capability | Maturity |
| --- | --- |
| TLS Hostname Verification Disabled | CORE |
| Hardcoded Secret | CORE |
| SQL Injection | VALIDATED |
| Command Injection | VALIDATED |
| SSRF | VALIDATED |
| Path Traversal | VALIDATED |
| Arbitrary File Read | VALIDATED |
| Arbitrary File Write | VALIDATED |
| XXE | VALIDATED |
| Unsafe Deserialization | VALIDATED |

There are 10 detection capabilities: 2 CORE and 8 VALIDATED. The installed
pack contains 19 capability-owned Semgrep variants, 29 total installed Semgrep
rules, 8 legacy Java EXPERIMENTAL rules default-off, and 2 existing Python
rules. Gitleaks owns secret detectors; its provider-owned detector count is not
treated as a new product rule count.

VALIDATED means enabled detection and guidance with an explicit maturity label;
it is not a production-accuracy claim and does not grant automatic fixing.

## Evidence and limits

The managed synthetic corpus reports **46 TP / 28 TN / 0 FP / 0 FN** across 71
synthetic cases. These are author-declared labels, not independent ground truth
and not production-grade accuracy. Versioned corpus and fixtures remain under
`tests/`; generated acceptance output is not a source-of-truth document.

The program preserves scanner ownership, underlying rule identity, source
coordinates, capability Family identity, occurrence accounting, and conservative
absence proof. A successful process without complete rule/path coverage is not
proof of absence. Compiler-grade cross-file analysis, arbitrary sanitizer proof,
exploitability, and gadget reachability are outside this program.

## Host relationship

The Rule Program is consumed by the existing Runtime Core and scanners. It does
not add a second Finding or authorization system. Host status is documented in
[Architecture](ARCHITECTURE.md) and [Project context](PROJECT_CONTEXT.md).

## R1 detection quality status

R1 Phase 1 corpus/evaluation and Phase 2 bounded fixes are locally complete.
Independently labelled Benchmark samples reveal substantial analysis limitations;
the R0 synthetic 0 FP/FN result is not production accuracy. Maturity remains
2 CORE and 8 VALIDATED.

SQLi now models single-argument Connection.prepareCall SQL templates; overloads
remain limited. Command injection adds local ProcessBuilder.command followed by
start, with command overwrite/reassignment handling and position-bounded command
list propagation. Constant SQL, bound values, fixed executables and bounded
constant/data arguments have safe regressions. No Cookie source expansion or
broad helper trust is adopted.

Cross-function, cross-file, arbitrary wrapper, builder/collection lifecycle,
constant propagation and selected framework abstractions remain known analysis
limitations. Array setters, alias-based starts and complex list mutations are
outside the new bounded setter model. Known FP/FN regressions retain independent
risk labels and explicit strict xfail reasons; they are not successful checks.
See `tests/corpus/r1/` for inputs and reproduction instructions. Generated
evaluation output remains ignored under `artifacts/r1/`. Release Preflight
follows review of the release candidate; no capability is promoted here.
