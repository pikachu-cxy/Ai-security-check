# Use with WorkBuddy

Version **0.3.14** supports global MCP, Hooks and Skill integration. Edits record paths; the end of a development task submits a combined check. Ordinary read-only chat does not start a scan.

## Configure globally

Download and verify the [full native bundle](../../downloads.md), extract to a stable short path, and retain the entire folder. Replace the example executable path with your actual location:

::: code-group
```powershell [Windows]
C:\ASR\security-check.exe prepare-scanners
C:\ASR\security-check.exe setup workbuddy --scope global --json
```
```sh [macOS]
./security-check/security-check prepare-scanners
./security-check/security-check setup workbuddy --scope global --json
```
:::

Configuration uses `WORKBUDDY_CONFIG_DIR`, then `CODEBUDDY_CONFIG_DIR`, then existing `~/.workbuddy-ai`, otherwise `~/.workbuddy`. It preserves unrelated MCP services, settings and Hooks. Keep the configured executable at its stable path. Existing project-level connections can create duplicate services; remove the old product entry through its original integration removal flow.

## Manually trust MCP after restart

1. Completely quit and reopen WorkBuddy.
2. Open the connectors / MCP management screen (labels vary by version).
3. Find `ai-security-runtime`, **manually select service trust and enable the connection**. Installation does not approve trust for you.
4. Confirm it is connected with **11 tools**. An old 80+ tool listing suggests a stale or duplicate connection.
5. In a new chat ask: `Only query the connected security service version and build. Do not edit or scan files.` It should report **0.3.14**.

## Try development

In a temporary Git project, ask:

```text
Create a Python command-line todo tool that adds, lists and completes tasks stored in a JSON file in this project. Perform basic verification and deliver the result.
```

The final check should cover edited files, with configured finding review before reporting. A follow-up read-only question should not trigger duplicate Stop messages from the completed task. A successful MCP connection alone does not prove automatic checks work.

This release reuses user-confirmed WorkBuddy desktop acceptance. CI additionally exercises setup and repeated setup at a path longer than 260 characters on Windows; it does not claim acceptance for every Windows desktop version.

Legacy project-only MCP setup remains available: `security-check setup workbuddy --path <project>`.
