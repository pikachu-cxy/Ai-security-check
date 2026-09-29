# Third-party notices

This Runtime installs or invokes the independently licensed scanner engines below. Engine licenses do not grant rights to third-party rule collections. The pinned LICENSE and NOTICE texts are preserved in the `security_runtime/licenses/` package directory.

| Component | Version | Copyright | License | Homepage | Attribution |
| --- | --- | --- | --- | --- | --- |
| Semgrep | 1.178.0 | Copyright Semgrep, Inc. and contributors | LGPL-2.1-only | https://semgrep.dev | Retain LICENSE and NOTICE; see SOURCE_OFFER.md for source availability |
| Gitleaks | 8.30.0 | Copyright (c) 2019 Zachary Rice | MIT | https://github.com/gitleaks/gitleaks | Retain LICENSE and NOTICE |
| Trivy | 0.74.0 | Copyright Aqua Security and contributors | Apache-2.0 | https://trivy.dev | Retain LICENSE and NOTICE |

## Rule packs

| Component | Version | Copyright | License | Source | Attribution |
| --- | --- | --- | --- | --- | --- |
| AI Security Runtime Core Rules (`ai-security-core`) | 1.0.0 | Copyright AI Security Runtime contributors | MIT | bundled local package | First-party authored rules |

The bundled rule pack is independently authored. Semgrep Community Rules and Semgrep Registry Rules are not bundled or fetched by default. User-provided rules remain under the user's own license and are never copied into the managed tool directory.

Other Python dependency license terms are distributed with their respective installed Python packages.
