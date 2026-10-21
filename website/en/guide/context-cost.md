# Usage monitoring and reports

Source version 0.3.9 adds one-step monitoring for the current Codex chat and report export. Install a build containing this capability and its companion Skill, restart Codex, and verify the actual build.

## Start and export

1. In the current project chat, ask **"Start usage monitoring for this chat."**
2. The assistant opens a local page and starts observation without asking you to find log files.
3. Continue the development or review task normally.
4. Use the stop-and-export control to download a ZIP containing an offline HTML report, JSON statistics, and measurement notes.

The page listens on loopback with a random access path. Monitoring does not request a model, start a scan, or authorize repairs. Missing identity, ambiguous logs, and unsupported hosts are reported rather than substituted with another recent chat. Automatic token association currently supports local Codex logs only.

## Interpret the measurements

| Measurement | Meaning |
| --- | --- |
| Chat tokens in this window | Difference between the nearest reported cumulative usage at start and end; includes development, discussion, and review. Unsettled usage can be missing. |
| Observation duration | Monotonic elapsed time, including waiting. |
| Associated tool time | Runtime calls verified for this session; concurrent intervals also have a union measure. Summed call time is not the user's wall-clock wait. |
| Development-only / security-only tokens | Unknown when they cannot be separated reliably. Do not derive them from tool-response bytes. |

Cached input is a subset of input tokens; reasoning output is a subset of output tokens. Do not add either twice. Missing baselines, log rotation, and incomplete observations stay visible. The end snapshot is fixed; repeated exports do not keep accumulating usage. The product does not estimate billing costs.

## Privacy and isolation

Monitoring is optional. Stopping, failing, or omitting it from a source distribution does not change core scans, task records, or authorization. Keep managed installation packages intact rather than deleting files inside them.

Automatic association reads bounded local log metadata and usage counts for the verified session. Monitoring records and exports exclude source code, prompts, response bodies, raw session identity, and log paths. It does not upload statistics or write host configuration. A temporary detailed-recording lease is released at the end.

Generic MCP statistics retain counts, bytes, timing, and opaque identity metadata for up to 14 days and 10,000 call events. Task-review source snapshots are separate records with different sensitivity; see [privacy](../reference/privacy.md).

## Maintainer queries

Use the executable for your [installation method](./installation.md#runtime-path), with these arguments:

```console
security-check context-usage status --json
security-check context-usage compare --baseline before --candidate after --json
```

`SECURITY_RUNTIME_CONTEXT_RUN` distinguishes experiments using a 1–64 character ASCII label; changes to the MCP startup environment require reconnecting. `SECURITY_RUNTIME_CONTEXT_MONITOR=0` disables generic collection without changing security behavior.

Explicit manual Codex imports use only the selected file:

```console
security-check context-usage import-codex --path before.jsonl --run before --json
security-check context-usage import-codex --path after.jsonl --run after --json
```

Raw JSONL may contain project content and must be protected separately. Imports have explicit file, line, and record limits. Reimporting does not double-count old usage; ambiguous overlapping runs or malformed records stay incomplete. Incomplete data does not produce a savings percentage. Byte changes and actual token changes are reported separately.

Use the same model, CLI, source, rules, prompt, and starting history for comparisons. Do not attribute all chat usage to the Runtime or compare cold preparation with a warm cache as equivalent runs. Full engineering details are in the [monitoring guide (Chinese)](https://github.com/pikachu-cxy/Ai-security-check/blob/feature/runtime-mvp/docs/guides/LIVE_MONITORING.zh-CN.md).
