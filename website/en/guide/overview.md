# Security checks alongside AI development

AI Security Runtime connects local security checks to Codex and Cursor. Develop normally: the Runtime records affected paths and scans the recorded files at closeout. Your agent reviews candidates against code, explains risks, and follows your handling decisions.

The current official release is **0.3.11**, with Windows x64, macOS Apple Silicon, and Intel bundles. A separate managed macOS installer prepares dedicated Python. See [downloads](../downloads.md) for checksums and the distinct build identities.

## Default workflow

Record edited paths → scan the recorded files at closeout → agent review → save risks and decisions → verify the original issue after an approved fix.

Ordinary development does not create a project-wide pre-edit baseline or require a whole-project scan. The agent may read related business logic to assess authorization or callers; that reading does not automatically expand static scan scope.

| Component | Responsibility |
| --- | --- |
| Local Runtime | Record paths, schedule checks, retain evidence and decisions, and validate workspace/session ownership |
| Scanners | OpenGrep code rules, Gitleaks secrets, Trivy applicable dependencies/configuration, and bounded native analysis |
| Host agent | Understand business logic, review triggers and safeguards, explain impact, and implement approved changes |
| User | Select issues to fix, defer, or exclude |

Rules depend on the selected files and installed rule pack. See [coverage](../reference/support.md#languages). Raw scanner candidates and evidence-backed agent conclusions remain distinct.

## Use it in your workflow

[Install](./quickstart.md), restart your editor, [verify the connection](./verify.md), and try the [demo](./demo.md). Full integration includes MCP, Skill, and Hooks; [manual MCP](./mcp.md) requires explicit tool use.

Read saved results without rescanning, view [local risks](./risk-handling.md) separately for Codex/Cursor or together, approve specific fixes, and optionally export [usage reports](./context-cost.md). Installation, scan completion, agent review, and fix verification are separate outcomes. Explicit strict workspace-diff audits retain their original baseline and protocol.
