# Third-party notices

This Runtime installs or invokes the following independently licensed scanner engines. Engine licenses do not grant rights to third-party rule collections. The full pinned LICENSE texts are preserved in `src/security_runtime/licenses/` and copied into managed binary directories at installation.

| Component | Version | Copyright | License | Homepage | Attribution |
| --- | --- | --- | --- | --- | --- |
| Gitleaks | 8.30.0 | Copyright (c) 2019 Zachary Rice | MIT | https://github.com/gitleaks/gitleaks | Retain LICENSE |
| Trivy | 0.74.0 | Copyright 2019-2020 Aqua Security Software Ltd. and contributors | Apache-2.0 | https://trivy.dev | Retain LICENSE and NOTICE |
| Semgrep OSS Engine | 1.178.0 | Copyright Semgrep, Inc. and contributors | LGPL-2.1-only | https://semgrep.dev | Retain LICENSE; redistribution has additional LGPL obligations |

## Rule packs

| Component | Version | Copyright | License | Source | Attribution |
| --- | --- | --- | --- | --- | --- |
| AI Security Runtime First-party Rules (`ai-security-core`) | 1.0.0 | Copyright AI Security Runtime contributors | MIT | Bundled local rules | First-party authored rules |

The bundled rule pack is independently authored. Semgrep Community Rules and Semgrep Registry Rules are not bundled or fetched by default. User-provided rules remain under the user's own license and are never copied into the managed tool directory.

Other Python dependency license terms are distributed with their respective installed Python packages. The engine list above describes the pinned scanner components directly managed by this Runtime.
