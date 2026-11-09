# AI Security Runtime — official agent installation guide

Release: 0.3.14. Supported editors for this release: Codex and Cursor only.
This guide implements the user's installation request; it does not grant permission to scan projects, change security settings, or overwrite unrelated configuration.

1. Identify the local operating system, architecture and requested editor. If the editor is ambiguous, ask which of Codex or Cursor to configure. Use local execution; a remote container cannot install into the user's desktop. WorkBuddy installation is not supported in this release.
2. Preserve existing settings and unrelated MCP servers, Hooks and Skills. Stop on configuration conflicts; do not delete or replace user-managed entries to force installation.
3. Use the official native installer below. Do not substitute a source checkout, Python development installation, or an unofficial mirror. The scripts select and verify the release archive before execution. Windows supports x64; macOS supports Apple Silicon and Intel.

Windows: run in ordinary PowerShell, replacing `cursor` with `codex` when requested:

```powershell
& ([scriptblock]::Create([Text.Encoding]::UTF8.GetString((Invoke-WebRequest -UseBasicParsing 'https://pikachu-cxy.github.io/Ai-security-check/install/windows.ps1').RawContentStream.ToArray()))) -Editor cursor
```

macOS: replace `cursor` with `codex` when requested:

```sh
curl --proto '=https' --tlsv1.2 -fsSL https://pikachu-cxy.github.io/Ai-security-check/install/macos.sh | bash -s -- cursor
```

4. On Windows, packaged hosts can redirect legacy AppData. The new default is `%USERPROFILE%\.asr`. If the installer reports redirected legacy reads or active old processes, explain the exact diagnostic and ask the user to close the editor and run the command in ordinary PowerShell. If legacy copies differ, do not guess which history to retain; obtain the user's choice before using `-LegacyAppData`. Preserve all original copies. Do not add sleeps, repeat downloads, scans or redundant probes to normal installation.
5. Use the installed program path printed by the installer. Check `runtime-info --json`, `preparation status`, and the installation receipt. Distinguish local files installed from scanners/data ready. Report actual version and build_id; version equality alone is insufficient. Background preparation may still be running. Do not claim success on a nonzero exit or incomplete receipt.
6. Ask the user to fully quit and reopen the editor. The current agent may terminate during restart; leave a short verification instruction first. Let the user handle login, trust and security prompts through the host's normal UI; do not bypass them.
7. After restart, use the actual connected service's `get_runtime_info` and preparation-status tool (discover its current schema) to verify the loaded build and readiness. If the original host connection cannot be tested, mark it pending; a separate test process is not desktop reconnection proof. Do not scan or modify a business project during installation.

Manual alternatives and editor-specific instructions:
- https://pikachu-cxy.github.io/Ai-security-check/guide/editors/codex.html
- https://pikachu-cxy.github.io/Ai-security-check/guide/editors/cursor.html
- https://pikachu-cxy.github.io/Ai-security-check/downloads.html
