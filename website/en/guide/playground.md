# Practice checklist

Use the isolated Git folder from the [demo](./demo.md). Record actual observations rather than requiring a fixed alert count. Do not execute the intentionally unsafe export function.

| Case | Action | What to observe |
| --- | --- | --- |
| Connection only | Ask for connection, version, and readiness; prohibit scans and edits. | Actual status is returned without starting a project scan. |
| Known issue | Save the demo's `os.system` version and request a static check of `demo.py`. | The file and rules actually run; the command path and external-input precondition are explained. |
| Fix verification | Approve the specific filename-validation and argument-list fix. | The explanation traces how the original command path was removed, with remaining unknowns retained. |
| Impact only | Ask which interfaces, callers, and tests a fix would affect, without editing. | Analysis is returned and the file remains unchanged. |
| Development-task review | With full integration, request `normalize_label(text)` in `labels.py`, then check the change. | Both the implementation and actual task-check status are returned. |

If a known issue is absent, verify the connection, enabled Python rules, saved file, and completed scope before treating the result as a detection gap. A manual MCP integration does not promise automatic post-edit orchestration.

For the ordinary label function, expected examples are `"  Hello  "` → `"hello"`, `"  MiXeD Case  "` → `"mixed case"`, and `"   "` → `""`. If you already have a Python environment, these can be ordinary functional checks. Record them as unrun if they were not executed; they do not replace security review.

## Keep a short record

For each case, note completed, failed, or incomplete, along with the actual build, file scope, component status, finding location, original verification record, and diagnostic. Keep or delete the isolated folder when finished. Share only sanitized observations when [reporting a problem](../reference/faq.md#report).

## Reconnect without repeating the test

Keep the development check reference. After reconnecting MCP in the original chat, read that same check and risk decisions without editing, rescanning, or creating a replacement. The scope, scan version, and decisions should remain readable; missing credentials are an integration diagnostic, not a reason to guess identity.

## Compare editor statistics

Ask to open risk statistics and select All editors, Codex, and Cursor. Check source labels, filtered counts, and read diagnostics. Reuse saved records; do not rerun scans merely to populate the page.
