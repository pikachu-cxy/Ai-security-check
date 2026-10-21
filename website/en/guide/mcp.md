# Manual MCP setup

Use this path when you manage the host's MCP configuration yourself. It creates a service connection without automatically installing host Skills or Hooks. For automatic development-task orchestration, use [full editor integration](./quickstart.md).

## Prepare the program

Verify and fully extract a platform bundle, keep it in a stable location, and run from its parent directory:

```powershell
.\security-check\security-check.exe prepare-scanners
.\security-check\security-check.exe mcp config --path "C:\work\your-project" --toml
```

Use `--json` instead of `--toml` for JSON output. On macOS, use `./security-check/security-check` and the actual absolute path of your Git project.

## Merge the generated entry

Merge the generated service entry into the configuration format and scope supported by your client. Preserve unrelated services and the generated absolute executable path, workspace binding, and environment. Do not copy another machine's paths or overwrite the whole configuration.

## Verify and request checks

Restart the host and perform [read-only installation verification](./verify.md). Then explicitly request a check in an isolated demo, specifying the intended scope. Confirm that the service returns results for the correct workspace.

MCP access alone does not establish automatic checks after every edit, fix approval handling, or task recovery. Those workflows depend on additional host integration and validation.
