# Documentation

This directory contains current, maintainable project facts. Historical
acceptance output belongs in Git history, not in `docs/`.

## Start here

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

- [Rule Program v1](RULE_PROGRAM.md)
- [Rule coverage matrix](RULE_COVERAGE_MATRIX.md)

## Remediation

- [Smart auto-remediation](SMART_AUTO_REMEDIATION.md)

## Verification

- [Functional verification](FUNCTIONAL_VERIFICATION.md)

## Extension / Development

- [Extending the Runtime](EXTENDING.md)

## Documentation lifecycle

- Long-term facts → `docs/`
- Test fixtures and ground truth → `tests/fixtures/` or the owning test
  package
- Temporary acceptance output → `artifacts/` or an ignored temporary directory
- Release artifacts → `dist/`
- Historical versions → Git history

Do not add generated snapshots such as `docs/foo-before.json`,
`docs/foo-after.json`, or `docs/foo-final-final.json` to the repository.
