# Verify installation

Check the actual editor connection, expected build, component readiness, and bound project path, then run an isolated example.

## 1. Query the connected service

Completely quit and reopen the editor. In a new chat in your intended project, send:

```text
Use actual AI Security Runtime tool calls to check installation status:
1. Is it connected? Report the version, build_id, and source commit.
2. Are code, secret, and dependency checks ready? List downloads, failures, or stale data.
3. Explicitly query the actual source root's absolute path. Is it accepted and correct?
4. Is the companion guidance available?
Do not scan or modify the project. Explain anything unverified and the next step.
```

## 2. Interpret the result

| Observation | Meaning and next step |
| --- | --- |
| Actual calls succeed, build matches, components and data are ready, path is correct | Continue with the demo. |
| Installation ended but components are downloading | [Observe preparation](./installation.md#preparation). |
| Configuration exists but tools cannot be called | The connection is not established; inspect startup errors. |
| Same version but different build or source | Compare the actual executable with the selected release. |
| Missing engine, startup failure, or stale data | Retain the specific component diagnostic and unavailable scope. |
| Different bound project | Open the right project and check the configuration scope. |
| `READY` with project state `NEEDS_SCAN` | Components are available; no project scan has been recorded. Request one when needed. |

### Select the actual project root

Open the directory containing the source and Git repository rather than an outer ZIP extraction folder. Ask the agent to supply that absolute root explicitly in the read-only status query. If rejected, check the directory, Git status, and returned diagnostic. A rejection code alone does not establish its cause or require reinstallation.

After switching from source development to a downloaded release, check that the editor starts the managed executable rather than Python in the old source directory. The default full-bundle installation root is `%LOCALAPPDATA%\AI-Security-Runtime-install` on Windows. Compare build ID and source commit even when the version number matches.

## 3. Perform a real check

Use the separate Git folder in [your first demo](./demo.md). It does not require running the vulnerable example or installing project dependencies. A completed check reports its actual file scope, execution status, findings, and limitations; file creation or connection success alone is insufficient.

## Connection troubleshooting {#connection}

Confirm the service is enabled in the editor and inspect its actual startup error. Fully exit old processes before checking a stale build. Keep the installation directory referenced by the configuration. Use the correct [executable path](./installation.md#runtime-path).

The local [connection-status commands](./installation.md#connection-status) inspect settings but do not replace a real editor call. Current full task review requires `task-review-plan-v3`, `task-result-delivery-v1`, and their companion tools. Update the Runtime that the configuration actually starts, then reconnect; replacing the Skill alone cannot add missing Runtime capabilities.

## Incomplete checks

Read the concrete cause: unavailable components, file count or size limits, unreadable paths, or missing pre-edit evidence are different limitations. An incomplete check is neither a discovered vulnerability nor a passing result. See [troubleshooting](../reference/faq.md#report).
