# Downloads

**License notice:** Use the license included in the downloaded version. The new repository license does not retroactively change published archives. See [licensing](./reference/legal).

Current release: **0.3.13**. The installers below and manual downloads use the same native bundles; no preinstalled Python is needed.

## Install by editor {#install}

[Codex](./guide/editors/codex.md) · [Cursor](./guide/editors/cursor.md) · [WorkBuddy](./guide/editors/workbuddy.md)

WorkBuddy requires manually trusting and enabling `ai-security-runtime` in its MCP management screen after restart.

## Native bundles {#windows}

| Platform | Download | Checksum |
| --- | --- | --- |
| Windows x64 | [zip](https://github.com/pikachu-cxy/Ai-security-check/releases/download/v0.3.13/ai-security-runtime-v0.3.13-windows-x64.zip) | [SHA256](https://github.com/pikachu-cxy/Ai-security-check/releases/download/v0.3.13/ai-security-runtime-v0.3.13-windows-x64.zip.sha256) |
| Mac Apple Silicon | [tar.gz](https://github.com/pikachu-cxy/Ai-security-check/releases/download/v0.3.13/ai-security-runtime-v0.3.13-macos-arm64.tar.gz) | [SHA256](https://github.com/pikachu-cxy/Ai-security-check/releases/download/v0.3.13/ai-security-runtime-v0.3.13-macos-arm64.tar.gz.sha256) |
| Mac Intel | [tar.gz](https://github.com/pikachu-cxy/Ai-security-check/releases/download/v0.3.13/ai-security-runtime-v0.3.13-macos-x64.tar.gz) | [SHA256](https://github.com/pikachu-cxy/Ai-security-check/releases/download/v0.3.13/ai-security-runtime-v0.3.13-macos-x64.tar.gz.sha256) |

Download the archive and matching checksum, verify, then extract and retain the complete `security-check` folder. GitHub “Source code” archives are for source development, not installation.

```powershell
Get-FileHash .\ai-security-runtime-v0.3.13-windows-x64.zip -Algorithm SHA256
Get-Content .\ai-security-runtime-v0.3.13-windows-x64.zip.sha256
```

## macOS installation {#macos}

[Codex](./guide/editors/codex.md#macos) and [Cursor](./guide/editors/cursor.md#macos) provide the current installer command. It detects the chip and downloads the corresponding 0.3.13 bundle.

### Manual macOS packages {#macos-packages}

```sh
# Apple Silicon
shasum -a 256 -c ai-security-runtime-v0.3.13-macos-arm64.tar.gz.sha256
tar -xzf ai-security-runtime-v0.3.13-macos-arm64.tar.gz
./security-check/security-check install codex
```

Choose `macos-x64` on Intel; replace `codex` with `cursor` for Cursor. WorkBuddy uses its [global setup instructions](./guide/editors/workbuddy.md).

## Source and acceptance {#build-details}

This release reuses completed local regressions and user-confirmed WorkBuddy desktop acceptance. CI validates the three new native bundles, compact MCP surfaces, and Windows-only long-path setup; it does not repeat the full local suite. Read the published evidence for actual results.

[Release](https://github.com/pikachu-cxy/Ai-security-check/releases/tag/v0.3.13) · [SHA256SUMS.txt](https://github.com/pikachu-cxy/Ai-security-check/releases/download/v0.3.13/SHA256SUMS.txt) · [release-manifest.json](https://github.com/pikachu-cxy/Ai-security-check/releases/download/v0.3.13/release-manifest.json) · [Evidence ZIP](https://github.com/pikachu-cxy/Ai-security-check/releases/download/v0.3.13/ai-security-runtime-v0.3.13-release-evidence.zip)

[Support boundaries](./reference/support.md) · [Changelog](./reference/changelog.md)
