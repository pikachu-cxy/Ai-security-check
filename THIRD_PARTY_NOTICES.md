# Third-party notices

This Runtime installs or invokes the independently licensed scanner engines below. Engine licenses do not grant rights to third-party rule collections. The pinned LICENSE and NOTICE texts are preserved in the `security_runtime/licenses/` package directory.

| Component | Version | Copyright | License | Homepage | Attribution |
| --- | --- | --- | --- | --- | --- |
| OpenGrep | 1.32.0 | Copyright OpenGrep, Semgrep and contributors | LGPL-2.1-only | https://github.com/opengrep/opengrep | Retain LICENSE and NOTICE; see SOURCE_OFFER.md for source availability |
| Semgrep | 1.178.0 | Copyright Semgrep, Inc. and contributors | LGPL-2.1-only | https://semgrep.dev | Retain LICENSE and NOTICE; see SOURCE_OFFER.md for source availability |
| Gitleaks | 8.30.0 | Copyright (c) 2019 Zachary Rice | MIT | https://github.com/gitleaks/gitleaks | Retain LICENSE and NOTICE |
| Trivy | 0.74.0 | Copyright Aqua Security and contributors | Apache-2.0 | https://trivy.dev | Retain LICENSE and NOTICE |
| OSV-Scanner | 2.6.0 | Copyright Google LLC and OSV-Scanner contributors | Apache-2.0 | https://github.com/google/osv-scanner | Retain LICENSE and NOTICE |

## Rule packs

| Component | Version | Copyright | License | Source | Attribution |
| --- | --- | --- | --- | --- | --- |
| OpenGrep Rules (`opengrep-rules`) | f1d2b562b414783763fd02a6ed2736eaed622efa | Copyright Semgrep, Inc. and rule contributors | LGPL-2.1-only WITH Commons-Clause | https://github.com/opengrep/opengrep-rules/tree/f1d2b562b414783763fd02a6ed2736eaed622efa | Upstream LICENSE retained; free personal distribution; Commons Clause restrictions apply |
| Bounded Java/Python dataflow (`ai-security-bounded-dataflow`) | 1.5.0 | AI Security Runtime contributors | Apache-2.0 | bundled local package | First-party authored; SQL, resolved cross-file Java/Python paths and exact Python io/codecs stream opens by default; other intrafile paths/command candidates experimental |
| Bounded Go SQL dataflow (`ai-security-go-sql`) | 1.0.0 | AI Security Runtime contributors | Apache-2.0 | bundled local package | First-party authored; same-package net/http to database/sql, at most two resolved call edges |

The bundled opengrep-rules pack is an archived fork of semgrep-rules, pinned by commit. Its LGPL-2.1 plus Commons Clause license is distinct from the engine license. It is not represented as permissively licensed or unrestricted for commercial/SaaS redistribution. User-provided rules remain under the user's own license and are never copied into the managed tool directory.

Other Python dependency license terms are distributed with their respective installed Python packages.

## Standalone bootloader and package dependencies

| Component | Version | Copyright | License | Homepage | Attribution |
| --- | --- | --- | --- | --- | --- |
| PyInstaller bootloader | 6.22.3 | PyInstaller Development Team | GPL-2.0-or-later WITH Bootloader-exception | https://pyinstaller.org | Bootloader exception permits distribution; retain this notice |
| MCP Python SDK | 1.29.0 | MCP contributors | MIT | https://github.com/modelcontextprotocol/python-sdk | Runtime dependency |
| PyYAML | 6.0.3 | PyYAML contributors | MIT | https://pyyaml.org | Runtime dependency |
| packaging | 26.3 | packaging contributors | Apache-2.0 OR BSD-2-Clause | https://packaging.pypa.io | Python dependency declaration parsing; original license texts included in standalone inventory |
| javalang | 0.13.0 | Copyright (c) 2013 Christopher Thunes | MIT | https://github.com/c2nes/javalang | Java 8 parser; original LICENSE retained |
| six | 1.17.0 | Copyright (c) 2010-2024 Benjamin Peterson | MIT | https://github.com/benjaminp/six | Parser dependency; original LICENSE retained |
| Managed CPython | 3.12.12 / 20260211 | Python Software Foundation and distribution contributors | Python-2.0 and included component licenses | https://github.com/astral-sh/python-build-standalone | Separate checksum-pinned download on first Semgrep preparation; preserve upstream license inventory; not bundled |
