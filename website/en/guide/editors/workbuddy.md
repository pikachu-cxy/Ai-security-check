# Install and use with WorkBuddy

0.3.14 supports Windows x64, Mac Apple Silicon, and Mac Intel. Installation configures user-level MCP, Skill, and four Hooks and starts scanner preparation.

## Recommended installation

Paste this request into your local WorkBuddy chat.

```text
Follow https://pikachu-cxy.github.io/Ai-security-check/install/agent.md to install AI Security Runtime for WorkBuddy on this computer. Preserve existing settings, verify the version, build and connection, and explain the restart and trust steps.
```

## Windows {#windows}

Run in regular PowerShell 5.1 or later. The script downloads and verifies the official package.

```powershell
& ([scriptblock]::Create([Text.Encoding]::UTF8.GetString((Invoke-WebRequest -UseBasicParsing 'https://pikachu-cxy.github.io/Ai-security-check/install/windows.ps1').RawContentStream.ToArray()))) -Editor workbuddy
```

## macOS {#macos}

Run in Terminal. The script selects and verifies the package for your Mac.

```sh
curl --proto '=https' --tlsv1.2 -fsSL https://pikachu-cxy.github.io/Ai-security-check/install/macos.sh | bash -s -- workbuddy
```

## Manual installation from the native bundle

[Download the archive and its SHA256 file](../../downloads.md), verify the archive, and extract the complete bundle. Run the command for your system from the parent of `security-check`.

::: code-group
```powershell [Windows]
.\security-check\security-check.exe install workbuddy
```

```sh [macOS]
./security-check/security-check install workbuddy
```
:::

## Restart and verify

Quit WorkBuddy completely and reopen it. In the MCP settings, check the `ai-security-runtime` service and review any trust prompt. Start a new chat and ask the agent to check the connected version, build ID, and scanner readiness. If the installer reports a conflict with legacy project configuration, follow the diagnostic and preserve the existing settings.

[Troubleshooting](../verify.md) · [Daily workflow](../workflow.md) · [Support](../../reference/support.md)
