# Install and use with Cursor

Full integration configures the user-level MCP connection, companion Skill, edit-event Hooks, and the routine-tool allowlist, then starts scanner preparation. Installation does not scan or modify your project. Start with a local, single-root Git workspace; remote and multi-root workflows are not listed as validated.

Current official native bundles: **0.3.10**.

## Windows {#windows}

Run this single command in regular **PowerShell 5.1 or later**, from any directory on Windows x64. It downloads the **0.3.10 official bundle**, verifies SHA256, extracts it, and installs the integration. No manual download, extraction, Python, Node.js, or Git installation is required.

```powershell
& ([scriptblock]::Create((Invoke-WebRequest -UseBasicParsing 'https://pikachu-cxy.github.io/Ai-security-check/install/windows.ps1').Content)) -Editor cursor
```

[Inspect the installer](https://pikachu-cxy.github.io/Ai-security-check/install/windows.ps1). No administrator privileges are required. Finish active checks first; existing product settings may be updated. Download, checksum, or configuration failures stop installation and preserve diagnostics. Retry the same command after resolving the error.

The installer prints the full preparation-status command. Downloads are retained under `%LOCALAPPDATA%\AI-Security-Runtime-downloads`; the installed runtime lives under `%LOCALAPPDATA%\AI-Security-Runtime-install`.

::: details Manual installation (fallback)
[Download and verify the complete bundle](../../downloads.md#windows), extract it, and run from the parent of `security-check`:

```powershell
.\security-check\security-check.exe install cursor
```
:::


## macOS {#macos}

Run in Terminal:

```sh
curl --proto '=https' --tlsv1.2 -fsSL https://pikachu-cxy.github.io/Ai-security-check/install/macos.sh | bash -s -- cursor
```

[Inspect the installer](https://pikachu-cxy.github.io/Ai-security-check/install/macos.sh) and its [SHA256](https://pikachu-cxy.github.io/Ai-security-check/install/macos.sh.sha256). Documentation deployment copies the maintained repository script directly. It detects Apple Silicon or Intel and prepares dedicated Python without requiring Python, Git, or Homebrew to be preinstalled. Keep `~/.local/share/AI-Security-Runtime-macos-trial`.

This uses the separate `macos-trial-v0.3.10` / Runtime 0.3.10 release. Existing product-owned Cursor settings may be updated. Finish active checks and avoid concurrent configuration edits. See [macOS validation boundaries](../../reference/support.md#macos-installation) and [paste warnings](../../reference/faq.md#macos-paste).

For a verified [manual native bundle](../../downloads.md#macos-packages), run `./security-check/security-check install cursor` from its parent directory. To switch back, reinstall from the original verified bundle, restart Cursor, and verify the build. Signing, notarization, and real desktop operation require separate validation.

## Ask your assistant to install

Paste this into **Cursor's Agent chat**, not a terminal:

```text
Install AI Security Runtime for Cursor using this guide:
https://pikachu-cxy.github.io/Ai-security-check/en/guide/editors/cursor.html
Verify the correct platform downloads and checksums, preserve unrelated services
and user changes, and report the installed build and component preparation status.
Do not scan or modify my project. Tell me when installation is finished so I can restart.
```

## Restart, verify, and try a task

Completely quit and reopen Cursor. In a new project chat, follow [installation verification](../verify.md), then try the [small development task](../quickstart.md#_3-try-a-small-development-task) and [first demo](../demo.md).

Whether routine tool calls need confirmation still depends on Cursor's mode and team policy. Fixes require your explicit authorization. Full integration describes installed components, not proof that every Cursor version, model, and desktop flow has passed acceptance. See [support](../../reference/support.md).

[Preparation and upgrades](../installation.md) · [Removal](../installation.md#uninstall) · [Daily workflow](../workflow.md)

## Reconnect and read saved results

Keep the original check reference and read it and its dispositions after reconnecting in the same chat, without rescanning. Hooks provide session ownership; users do not enter credentials and agents must not invent them. Default scans cover recorded files; related business logic is reviewed by the agent as needed. The managed macOS release predates the native 0.3.10 build and has its own source identity.
