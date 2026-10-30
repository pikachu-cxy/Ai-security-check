# Changelog

Source versions, published assets, CI acceptance, and real desktop validation are tracked separately. See [downloads](../downloads.md) and the original [engineering progress (Chinese)](https://github.com/pikachu-cxy/Ai-security-check/blob/feature/runtime-mvp/docs/DEVELOPMENT_PROGRESS.md).

## 0.3.11 · Official release

This release reduces temporary generated files, mock projects, and test fixtures entering source checks. See [downloads](../downloads.md) for native bundles and one-command installation; published assets and checksums are recorded in [v0.3.11](https://github.com/pikachu-cxy/Ai-security-check/releases/tag/v0.3.11).

- Agents place disposable development files in unique OS temporary directories outside the workspace, without asking users to configure paths.
- Task output declarations, bounded exclusions, and raw observation records remain available; explicit edits and tracked source take precedence.
- Formal tests and new untracked source remain subject to the existing observation rules. Entire test directories are not excluded.
- Specific scanner failure codes are preserved, and Windows long-path enumeration is corrected.

Focused release validation retains relevant regressions, compliance, package integrity, and native acceptance on all three platforms. Managed macOS installation uses `macos-trial-v0.3.11` with its own build identity.

## 0.3.10 · Official release

Published on 2026-10-28 UTC: [v0.3.10](https://github.com/pikachu-cxy/Ai-security-check/releases/tag/v0.3.10), with three native bundles from `082b9c1`. The [successful release workflow](https://github.com/pikachu-cxy/Ai-security-check/actions/runs/40706996250) completed focused regressions, installation checks, and native package acceptance. See [downloads and evidence](../downloads.md#build-details).

- Default development records edited files and scans at closeout without a project-wide baseline; strict audits retain their protocol.
- OpenGrep code rules, Gitleaks secrets, and Trivy dependencies are the defaults. OSV is not an automatic fallback.
- Cursor session routing, reconnect reads, and routine-tool allowlist integration; host approval policies still apply.
- Local risk statistics read Codex and Cursor records, separately or together, preserving source and disposition without cross-editor deduplication.
- Raw candidates and agent review remain distinct; fixes are verified against the original risk.
- Release acceptance follows the current scanner design; larger repair-ticket delivery is preserved within response limits.

Managed macOS installation separately uses the public `macos-trial-v0.3.10` build, which predates the native release. Matching version numbers do not establish the same source or build. Documentation deployment copies `distribution/macos/install.sh` directly and checks both architecture assets.

The following entries are historical, not current installation instructions.

## 0.3.9 · Official release

Published on 2026-10-21: [v0.3.9](https://github.com/pikachu-cxy/Ai-security-check/releases/tag/v0.3.9), with native bundles built from `fa1a26b`. The [successful release run](https://github.com/pikachu-cxy/Ai-security-check/actions/runs/39623506500) completed focused Windows/macOS regressions, compliance, integrity, and native acceptance on all three platforms; it did not rerun the complete development suite. Native bundles and managed macOS installation have separate identities. See [downloads](../downloads.md).

- Windows x64, Mac Apple Silicon, and Mac Intel bundles, matching SHA256 files, source metadata, and acceptance evidence.
- A separate managed Semgrep environment when an automatically discovered system tool cannot provide a verifiable execution identity. Offline mode, explicit selections, and managed-component failures keep their diagnostics. Managed macOS delivery uses `macos-trial-v0.3.9.3`.
- Distinct diagnostics for missing tools, unverifiable identity, missing local OSV databases, expired data, and unknown update times.
- Stronger redaction of credential-bearing template expressions while retaining pure variable references, plus provenance for literal redaction markers. Historical evidence is not reconstructed.
- User-language explanations that distinguish unverified scanner candidates from reviewed risks, combine repeated check gaps, and carry forward existing authorization for the same scope.

- Current-chat Codex usage monitoring with verified session association and HTML/JSON report export.
- Separate chat tokens, observation duration, tool totals, and concurrent-time union; unknown security-only or development-only tokens remain unknown.
- Optional monitoring independent of core scans, review records, and repair authorization.
- Full sanitized long-line evidence for new tasks, fragmented within actual response budgets; complete character delivery is required for coverage.
- Original task recovery, cumulative delivery accounting, and deduplicated evidence remain in place. Previously lost preimages are not fabricated.
- File-scoped checks, identity-verified full-project scan reuse, compact summaries, pagination, and MCP progress remain available. Read-only queries do not imply a new project scan.
- English README and `/en/` documentation with the same capability, support, privacy, and licensing boundaries as the Chinese guides.

The entries below are historical records, not current installation instructions. CI acceptance does not replace real desktop validation or Apple signing and notarization.

## 0.3.8 · Developer Alpha

Published 2026-10-20, with refreshed bundles and per-platform evidence:

- Compact scan summaries, pagination, and short review receipts, with explicit access to full output.
- Versioned guidance loading and deduplication, shared progress and timing, explicit file scopes, and identity-verified full-project scan reuse.
- Context-cost measurement that separates response bytes from actual host token usage.
- Shared Windows/macOS and Codex/Cursor core behavior, with desktop validation tracked separately.

## 0.3.7 and 0.3.6

- Credential-focused source redaction that preserves ordinary code literals and comments.
- Required evidence reading and review-unit submission before closing a task.
- v3 review and result delivery, original-finding verification, recovery, and managed Skill upgrades.
- Windows private-input and temporary-path handling, plus separately tracked macOS runtime compatibility changes.

The [full Chinese history](../../reference/changelog.md) retains detailed CI counts and artifact identities. Do not apply an older version's acceptance result to a new build.

## Still separate or planned

Current macOS real-machine and Cursor desktop acceptance, Apple signing/notarization, and user-selectable online/local vulnerability lookup remain distinct from the features above. A managed installation command is available for macOS; there is no general `npx` or remote PowerShell installation entry.
