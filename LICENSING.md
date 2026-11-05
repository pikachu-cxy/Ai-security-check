# Licensing model

Copyright (c) 2026 **pikachu-cxy**, for portions owned by that author.

AI Security Runtime uses the **Personal Noncommercial Source-Available License
1.0** in [LICENSE](LICENSE), identified as
`LicenseRef-AI-Security-Runtime-Personal-Noncommercial-1.0`.
It is source-available with use restrictions, not OSI-approved open source.
LICENSE controls; [EULA.md](EULA.md) adds operational terms.

## Permissions

| Activity | Default permission |
| --- | --- |
| Individual learning, personal research and noncommercial hobby projects | Allowed |
| Personal modifications kept private | Allowed; no publication required |
| Free noncommercial redistribution, original or modified | Same license, notices and complete corresponding source required |
| Closed-source distribution of covered Runtime or derivatives | Not allowed |
| Company internal use or use on behalf of an organization or client | Prior separate written authorization required, even if unpaid |
| Paid consulting, commercial development, integration, resale or hosting | Prior separate written authorization required |
| Scanning an independent project | Does not require publishing that project's source; the purpose of Runtime use must still be permitted |

Personal means a natural person acting personally, not for an employer or
organization. Free downloads and individual accounts do not exempt business use.
Public binary distributions must provide matching public source while offered;
private redistribution must provide source to the same recipients. See LICENSE
for complete conditions and SOURCE_OFFER.md for source guidance.

## Separate components

Files explicitly marked `SPDX-License-Identifier: Apache-2.0`, including
`src/security_runtime/plugin_api.py`, retain Apache-2.0. Its text is in
`LICENSES/Apache-2.0.txt`. Future SDKs, examples and rules are not automatically
Apache-2.0; they must be explicitly marked.

OpenGrep, historical Semgrep, Gitleaks, Trivy, the MCP SDK and other dependencies
retain their own licenses. Bundled `opengrep-rules` retain upstream LGPL-2.1 and
Commons Clause terms in `src/security_runtime/rules/LICENSE`; the former
`ai-security-core` YAML pack is no longer bundled. User-provided rules retain
their original licenses. See THIRD_PARTY_NOTICES.md and SOURCE_OFFER.md.
Neither this license nor a first-party commercial agreement overrides these terms.

## Versions, ownership and contributions

This policy applies only to source and builds distributed with this license.
Previously published releases retain their accompanying terms and existing grants
are not revoked. Website updates do not change old release archives.

The GitHub name `pikachu-cxy` identifies the project author; it is not a company
name or a claim to other contributors' rights. Preserve their notices. Before
accepting contributions, establish explicit terms covering the target component
and any rights needed for commercial relicensing. Do not assume a pull request
transfers copyright or grants relicensing rights.

## Commercial contact

Request written authorization from `pikachu-cxy` via the
[project repository](https://github.com/pikachu-cxy/Ai-security-check).
Commercial contracts should identify the actual legal parties and the rights
they control. Qualified counsel should review the terms for the intended jurisdiction.
