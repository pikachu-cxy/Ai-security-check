# Changelog

Source versions, published assets, CI acceptance, and real desktop validation are tracked separately. See [downloads](../downloads.md) and the original [engineering progress (Chinese)](https://github.com/pikachu-cxy/Ai-security-check/blob/feature/runtime-mvp/docs/DEVELOPMENT_PROGRESS.md).

## English documentation · 2026-10-21

- Added an English main README and retained the full Chinese README.
- Added an English documentation locale, navigation, search interface, and guides for installation, workflows, coverage, privacy, and troubleshooting.
- Kept release status and the proprietary Core / Apache-2.0 component boundary explicit.

## 0.3.9 · Official release

- If an automatically discovered system Semgrep cannot provide a verifiable execution identity, online installation prepares a separate managed environment. Offline mode, explicit selections, and broken managed components retain their diagnostics. The macOS installation script updates to managed delivery `macos-trial-v0.3.9.3` with the same fix.

This release uses focused regressions for current changes plus native platform acceptance; it does not rerun the complete development test suite.

- Official release with Windows x64, Mac Apple Silicon, and Mac Intel bundles, matching SHA256 files, source metadata, and acceptance evidence. Publication waits for the complete release gates; documentation deploys again after successful publication.


Source update dated 2026-10-21. Native bundles and managed macOS installation are built and validated separately; verify actual publication in [release Actions](https://github.com/pikachu-cxy/Ai-security-check/actions/workflows/release.yml).

- Current-chat Codex usage monitoring with verified session association and HTML/JSON report export.
- Separate chat tokens, observation duration, tool totals, and concurrent-time union; unknown security-only or development-only tokens remain unknown.
- Optional monitoring independent of core scans, review records, and repair authorization.
- Full sanitized long-line evidence for new tasks, fragmented within actual response budgets; complete character delivery is required for coverage.
- Original task recovery, cumulative delivery accounting, and deduplicated evidence remain in place. Previously lost preimages are not fabricated.

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
