# Other MCP clients

For Claude Code, VS Code / Copilot, Qoder, CodeBuddy, or another client, first confirm support for launching a local **stdio MCP** service and its current configuration format.

| Client | Current integration boundary |
| --- | --- |
| Codex | [Full integration](./codex.md); primary workflow. |
| Cursor | [Full integration](./cursor.md); validate a local single-root Git workspace first. |
| WorkBuddy | [Project-level MCP](./workbuddy.md); actual desktop calls require verification. |
| Claude Code, VS Code / Copilot | Generic manual MCP; no product-specific installer or complete workflow acceptance. |
| Qoder, CodeBuddy | Conditional manual MCP setup; no registered native edit-event adapter. |

## Setup

1. Download, verify, and fully extract a platform bundle to a stable location.
2. Follow [manual MCP setup](../mcp.md) to prepare components and generate project-bound configuration.
3. Merge the entry into the format supported by this client, preserving other services.
4. Restart and request a read-only connection check for the correct project.
5. Explicitly request a check in the [isolated demo](../demo.md) and verify the returned scope and status.

An available tool list does not prove a check ran. Client MCP support does not establish automatic edit checks, fix authorization, or task recovery. Preserve actual diagnostics and consult [support](../../reference/support.md).
