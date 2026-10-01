# Third-party notices

This Runtime installs or invokes the independently licensed scanner engines below. Engine licenses do not grant rights to third-party rule collections. The pinned LICENSE and NOTICE texts are preserved in the `security_runtime/licenses/` package directory.

| Component | Version | Copyright | License | Homepage | Attribution |
| --- | --- | --- | --- | --- | --- |
| Semgrep | 1.178.0 | Copyright Semgrep, Inc. and contributors | LGPL-2.1-only | https://semgrep.dev | Retain LICENSE and NOTICE; see SOURCE_OFFER.md for source availability |
| Gitleaks | 8.30.0 | Copyright (c) 2019 Zachary Rice | MIT | https://github.com/gitleaks/gitleaks | Retain LICENSE and NOTICE |
| Trivy | 0.74.0 | Copyright Aqua Security and contributors | Apache-2.0 | https://trivy.dev | Retain LICENSE and NOTICE |
| OSV-Scanner | 2.6.0 | Copyright Google LLC and OSV-Scanner contributors | Apache-2.0 | https://github.com/google/osv-scanner | Retain LICENSE and NOTICE |

## Rule packs

| Component | Version | Copyright | License | Source | Attribution |
| --- | --- | --- | --- | --- | --- |
| AI Security Runtime Core Rules (`ai-security-core`) | 1.1.0 | Copyright AI Security Runtime contributors | Apache-2.0 | bundled local package | First-party authored rules |

The bundled rule pack is independently authored. Semgrep Community Rules and Semgrep Registry Rules are not bundled or fetched by default. User-provided rules remain under the user's own license and are never copied into the managed tool directory.

Other Python dependency license terms are distributed with their respective installed Python packages.

## Standalone bootloader and package dependencies

| Component | Version | Copyright | License | Homepage | Attribution |
| --- | --- | --- | --- | --- | --- |
| PyInstaller bootloader | 6.22.3 | PyInstaller Development Team | GPL-2.0-or-later WITH Bootloader-exception | https://pyinstaller.org | Bootloader exception permits distribution; retain this notice |
| MCP Python SDK | 1.29.0 | MCP contributors | MIT | https://github.com/modelcontextprotocol/python-sdk | Runtime dependency |
| PyYAML | 6.0.3 | PyYAML contributors | MIT | https://pyyaml.org | Runtime dependency |
| Managed CPython | 3.12.12 / 20260211 | Python Software Foundation and distribution contributors | Python-2.0 and included component licenses | https://github.com/astral-sh/python-build-standalone | Separate checksum-pinned download on first Semgrep preparation; preserve upstream license inventory; not bundled |
