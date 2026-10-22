# Security checks alongside AI development

AI Security Runtime connects security checks to your coding assistant. Ask for a development change in Codex or Cursor, review the evidence and potential impact, decide which finding to address, and verify the fix against the original issue.

The current source version is **0.3.9 / Official release**. Native bundles and the managed macOS installer are separate releases. Check [downloads](../downloads.md) for public assets and [support](../reference/support.md) for actual validation boundaries.

## When to use it

- Review code and configuration changes while an agent implements a feature.
- Understand a finding's location, trigger conditions, safeguards, and unknowns.
- Assess the impact of a fix before authorizing it.
- Keep the original finding and its verification linked across interruptions.

## Responsibilities

| Component | Responsibility |
| --- | --- |
| Host agent | Understand the task, read relevant code, explain risks, and make authorized changes. |
| Local Runtime | Save the baseline, coordinate checks, and retain evidence, decisions, and verification records. |
| Scanning engines | Execute installed code rules, secret detection, and supported dependency checks. |

The Runtime does not embed an independent language model to replace the host agent. Full integration includes **Runtime + MCP + Skill + Hooks**; [manual MCP setup](./mcp.md) provides the service without automatic task orchestration.

## One connected workflow

Capture the workspace before editing → develop normally → check the changes and relevant context → explain risks → obtain the user's decision → verify the original finding after an approved fix.

Ordinary chat, read-only questions, and unchanged tasks should not trigger a project scan. Failed or incomplete checks retain their actual limitations.

## Current scope

Installed rule subsets cover Java, Python, and JavaScript/TypeScript, alongside secret checks, recognizable dependency manifests, and bounded contextual review. This is a developer preview, not proof that a project is secure.

Community rules and the public scanner extension API are Apache-2.0 licensed. The Runtime Core is proprietary; see [licensing](../reference/legal.md).

[Get started](./quickstart.md) · [Daily workflow](./workflow.md) · [Data and privacy](../reference/privacy.md)
