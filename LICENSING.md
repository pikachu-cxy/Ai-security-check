# Licensing model

AI Security Runtime uses a **closed-core, open-ecosystem** licensing model.

## Default rule

Unless a file or component explicitly states another license, it is part of
**AI Security Runtime Core** and is proprietary under the root `LICENSE` and
the applicable `EULA.md`.

A private repository, a downloadable binary, or a free product tier does not
change this default license.

## Proprietary components

The following categories are intended to remain proprietary unless explicitly
relicensed:

- Security Runtime core implementation
- scanner planning and orchestration
- risk and policy engines
- agent-runtime guard logic
- advanced/commercial rule packs
- package, Skill, MCP, and threat intelligence
- enterprise governance features
- cloud/backend services
- commercial data and signatures

## Apache-2.0 components

The following components are intended to be available under Apache License 2.0
when distributed or published:

- files explicitly carrying `SPDX-License-Identifier: Apache-2.0`;
- the public scanner/plugin extension contract;
- the bundled `ai-security-core` community rule pack;
- future public SDKs, schemas, integration specifications, examples, and
  community rules when explicitly marked Apache-2.0.

The full Apache-2.0 license is available at `LICENSES/Apache-2.0.txt`.

Open components do **not** cause the proprietary Runtime as a whole to become
open source.

## Third-party software

Semgrep, Gitleaks, Trivy, the MCP SDK, Python dependencies, and other
third-party components remain under their own licenses. Their license terms do
not grant rights to proprietary AI Security Runtime code.

See `THIRD_PARTY_NOTICES.md` and `SOURCE_OFFER.md`.

## Rule-pack policy

- `ai-security-core`: Apache-2.0 community/base rules.
- future community rule packs: Apache-2.0 when explicitly marked.
- future Pro / intelligence / commercial rule packs: proprietary unless
  otherwise stated.
- user-provided rules: remain under the user's own license and are not
  relicensed by the Runtime.

## Contribution policy

Do not accept external contributions to proprietary Core under an ambiguous
license.

Before opening public contribution, add a deliberate contribution policy
(CLA/DCO or equivalent) that clearly states whether a contribution targets an
Apache-2.0 component or proprietary Core.

## Before public commercial release

Replace placeholder/project-name copyright ownership with the correct legal
copyright holder or company name and have the EULA reviewed for the
jurisdictions where the product will be distributed.
