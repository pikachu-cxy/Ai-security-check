---
layout: home
title: Security checks for AI coding
description: Review changes, understand risks, approve fixes, and verify the original finding.
hero:
  name: AI Security Runtime
  text: AI writes code. Keep security evidence in the workflow.
  tagline: Version 0.3.11 for Windows and Mac. OpenGrep code checks, Gitleaks secrets, Trivy dependencies, and evidence-backed agent review of your recorded files.
  image:
    src: /logo.svg
    alt: AI Security Runtime
  actions:
    - theme: brand
      text: Get started
      link: /en/guide/quickstart
    - theme: alt
      text: How it works
      link: /en/guide/overview
    - theme: alt
      text: Language coverage
      link: /en/reference/support#languages
features:
  - title: Review the actual changes
    details: Record affected files during editing and scan the combined scope at closeout, without a project-wide baseline.
  - title: Understand the evidence
    details: Scanners and your host agent explain the location, trigger conditions, existing safeguards, and remaining unknowns.
  - title: Choose what to fix
    details: Approve a specific fix, defer it, or record an exclusion with its rationale. Findings and user decisions remain distinct.
  - title: Compare editor risk records
    details: View local Codex and Cursor records separately or together, preserving their sources and handling decisions.
  - title: Verify the original finding
    details: Link fixes to their original risks. A new scan with zero findings does not replace verification of an earlier issue.
---

## Connect your editor

[Codex installation](./guide/editors/codex.md) · [Cursor installation](./guide/editors/cursor.md) · [Other MCP clients](./guide/editors/other.md)

Full integration includes the Runtime, MCP connection, companion Skill, and Hooks. Manual MCP setup is also available.

## Know the boundaries

Checks run locally; semantic review is performed by your host agent under its own data policies. Coverage depends on installed rules, engines, vulnerability data, and the files actually reviewed. See [support](./reference/support.md), [privacy](./reference/privacy.md), and [licensing](./reference/legal.md).
