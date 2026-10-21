# Use with WorkBuddy

WorkBuddy currently has project-level MCP setup. Automatic edit checks and the complete real desktop workflow have not completed acceptance.

## Configure the project

Download and verify a [full bundle](../../downloads.md), extract it to a stable location, and replace the project path below with your actual local Git project:

::: code-group
```powershell [Windows]
.\security-check\security-check.exe setup workbuddy --path "C:\work\your-project"
```
```sh [macOS]
./security-check/security-check setup workbuddy --path "/Users/you/work/your-project"
```
:::

This writes the project's `.workbuddy/mcp.json`. Prepare components separately using [manual preparation](../installation.md#manual-preparation). Keep the program directory referenced by the configuration.

## Verify and use

Reopen the project and follow [read-only verification](../verify.md). Actual desktop calls must succeed and return the correct workspace and readiness state. Configuration or a test client alone does not establish this.

Then explicitly request a [demo check](../demo.md) without modifying or executing the sample. Request checks whenever needed; this integration does not promise automatic post-edit checks or automatic repair continuation.
