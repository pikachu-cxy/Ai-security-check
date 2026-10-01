# Trivy capability decoupling acceptance

The default registry runs `trivy-vuln` (`--scanners vuln`) for DEPENDENCY_VULN and `trivy-misconfig` (`--scanners misconfig`) for IAC_MISCONFIG. Both resolve the same pinned Trivy engine, with serialized engine preparation and concurrent independent scans. Only the vulnerability provider prepares vulnerability data. The IaC snapshot contains only planned Dockerfile, Terraform and YAML files; it has no contextual Maven manifests. Gitleaks is the default SECRET_SCAN provider. Container, SBOM and license capabilities are no longer advertised by these source providers.

Real Jeepay source execution on 2026-10-01, installed Trivy 0.74.0 and Gitleaks 8.30.0:

| Provider | Result | Duration | Findings |
| --- | --- | ---: | ---: |
| trivy-vuln | FAILED / MAVEN_RATE_LIMITED | 2,899 ms | 0 |
| trivy-misconfig | SUCCESS | 1,221 ms | 14 |
| gitleaks | SUCCESS | 2,650 ms | 9 |

SECRET_SCAN and IAC_MISCONFIG are EXECUTED despite the dependency provider's failure. The raw normalized results are in [trivy-decoupling-evidence.json](trivy-decoupling-evidence.json). This focused capability acceptance does not execute Semgrep; CODE_SAST is consequently UNAVAILABLE in that evidence. It does not replace the separate complete rule-stage evidence. SUCCESS for IaC means the planned local Trivy checks completed, not full cloud or deployment coverage. Newly visible IaC findings remain scanner output requiring review.

Regression verification: the full suite initially passed 229 tests with two stale assertions failing (three-provider count and last-row failure identity). Those assertions were corrected to four providers and the explicit dependency provider. Targeted suites verify independent commands/scope, no IaC vulnerability DB preparation, no Trivy secret capability, serialization of shared engine preparation, Maven diagnostics/storage/MCP/human outputs, doctor, progress, and Alpha behavior. Complete final-suite verification is repeated with the following OSV integration.
