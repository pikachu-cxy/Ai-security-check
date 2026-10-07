# Rule Program v1

Rule Program v1 is capability-first. It maps:

`Capability → underlying scanner rules → Finding Family / Episode → Policy → remediation / proof`

The product identity is the capability manifest at
[`src/security_runtime/rules/capabilities.json`](../src/security_runtime/rules/capabilities.json).
Catalog and YAML files are execution definitions, not the product quality measure.

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

## Next stage

R1 Detection Quality Hardening starts with real OSS/internal corpora, independent
ground truth, FP/FN measurement, precision/recall, and evidence-based CORE
promotion. No capability is promoted because this synthetic corpus is green.
