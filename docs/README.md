# Documentation

This directory contains current, maintainable project facts. Historical
acceptance output belongs in Git history, not in `docs/`.

## Start here

- [R2.2 security review contract](SECURITY_REVIEW.md)
- [Windows experience](WINDOWS_EXPERIENCE.md) / [中文体验](WINDOWS_EXPERIENCE.zh-CN.md)

- [Project context](PROJECT_CONTEXT.md) — the source of truth for resuming an
  AI-agent or developer session.
- [Architecture](ARCHITECTURE.md)
- [Decisions](DECISIONS.md)

## Architecture

- [Architecture](ARCHITECTURE.md)
- [Decisions](DECISIONS.md)
- [Functional verification boundary](FUNCTIONAL_VERIFICATION.md)

## Host integration

- [Codex integration](CODEX_INTEGRATION.md)
- Cursor's current verified state is recorded in
  [Project context](PROJECT_CONTEXT.md) and [Architecture](ARCHITECTURE.md).

## Detection / Rule Program

- [Rule foundation](RULE_FOUNDATION.md) — Java and JavaScript/TypeScript API scope,
  Hook measurement and the six-step local experience checklist.
- [Rule source inventory](RULE_SOURCE_INVENTORY.md) — upstream license decisions
  and the independent first-party implementation boundary.
- [Rule Program v1](RULE_PROGRAM.md)
- [Rule coverage matrix](RULE_COVERAGE_MATRIX.md)
- [Finding quality baseline](FINDING_QUALITY.md) — R2.1 independent review
  contract, stable correlation, local corpus workflow and metrics.
- [Scan target selection](SCAN_TARGET_SELECTION.md) — binary-document exclusions,
  bounded discovery diagnostics and coverage boundaries.

## Remediation

- [Smart auto-remediation](SMART_AUTO_REMEDIATION.md)

## Verification

- [Functional verification](FUNCTIONAL_VERIFICATION.md)

## Extension / Development

- [Extending the Runtime](EXTENDING.md)
- [升级与扫描入口优化清单](UPGRADE_AND_SCAN_USABILITY.zh-CN.md) — pending work,
  code-grounded gaps, acceptance gates and the next Codex development request.

## Documentation lifecycle

- Long-term facts → `docs/`
- Test fixtures and ground truth → `tests/fixtures/` or the owning test
  package
- Temporary acceptance output → `artifacts/` or an ignored temporary directory
- Release artifacts → `dist/`
- Historical versions → Git history

Do not add generated snapshots such as `docs/foo-before.json`,
`docs/foo-after.json`, or `docs/foo-final-final.json` to the repository.
