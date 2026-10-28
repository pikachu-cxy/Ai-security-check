# Install and use with Codex

Full integration configures the user-level MCP connection, companion Skill, and Hooks, then starts scanner preparation. Initial preparation needs network access. Installation does not scan or modify your business project. The supported starting point is a local, single-root Git workspace.

Current official native bundles: **0.3.10**.

## Windows {#windows}

[Download and verify the Windows x64 bundle](../../downloads.md#windows). Keep the whole extracted folder. From the directory containing `security-check`, run in PowerShell:

```powershell
.\security-check\security-check.exe install codex
```

The bundle includes Python. If the executable is not found, check the extraction level and terminal directory.

## macOS {#macos}

Run this single command in Terminal:

```sh
curl --proto '=https' --tlsv1.2 -fsSL https://pikachu-cxy.github.io/Ai-security-check/install/macos.sh | bash -s -- codex
```

[Inspect the installer](https://pikachu-cxy.github.io/Ai-security-check/install/macos.sh) and its [SHA256](https://pikachu-cxy.github.io/Ai-security-check/install/macos.sh.sha256). Documentation deployment copies the maintained repository script directly. It detects Apple Silicon or Intel, verifies its downloads, and prepares dedicated Python. No preinstalled Python, Git, or Homebrew is needed. The program is stored in `~/.local/share/AI-Security-Runtime-macos-trial`; keep that directory.

The managed installer uses `macos-trial-v0.3.10` / Runtime 0.3.10. Existing Codex configuration owned by this product may be updated; finish active checks first and avoid editing configuration during installation. There is no Apple Developer ID signing or notarization guarantee. See [macOS support](../../reference/support.md#macos-installation) and [paste warnings](../../reference/faq.md#macos-paste).

For a verified [manual native bundle](../../downloads.md#macos-packages), run `./security-check/security-check install codex` from its parent directory instead. To switch back, use the original verified bundle's installer, restart, and verify the actual build; an earlier system-policy rejection can still apply.

## Ask your assistant to install

Paste this into a **local Codex chat**, not a terminal:

```text
Install AI Security Runtime for Codex using this guide:
https://pikachu-cxy.github.io/Ai-security-check/en/guide/editors/codex.html
Use the appropriate platform installer, verify downloads and checksums, preserve
unrelated services and user changes, and report the installed build and preparation status.
Do not scan or modify my project. Wait until installation finishes before asking me to restart.
```

## Restart and verify

Completely quit and reopen Codex after installation finishes. Open a new chat in the intended project, review the host's connection and Hook trust prompts, and follow [verification](../verify.md). Component downloads may still be running; [check preparation](../installation.md#preparation) rather than running a second installation command.

Then try the [small development task](../quickstart.md#_3-try-a-small-development-task) and the [security demo](../demo.md).

[Daily workflow](../workflow.md) · [MCP-only setup](../mcp.md) · [Upgrades and removal](../installation.md#uninstall)

## Reconnect and read saved results

Keep the original check reference and read it and its dispositions after reconnecting in the same chat, without rescanning. Hooks provide session ownership; users do not enter credentials and agents must not invent them. Default scans cover recorded files; related business logic is reviewed by the agent as needed. The managed macOS release predates the native 0.3.10 build and has its own source identity.
