# Downloads and installation

Source version: **0.3.9 Developer Alpha**. Native full bundles and managed macOS installation have separate release and build identities. Only assets visible on a public release are available downloads; a source version or a running workflow does not establish publication.

## Windows full bundle {#windows}

Open the [native releases](https://github.com/pikachu-cxy/Ai-security-check/releases) and select a published full bundle with its matching SHA256 file. The target release for the current source is **v0.3.9**; while it is not public, the previous published full release is [v0.3.8](https://github.com/pikachu-cxy/Ai-security-check/releases/tag/v0.3.8).

| Platform | Archive name on the selected release |
| --- | --- |
| Windows x64 | `ai-security-runtime-v<version>-windows-x64.zip` |
| Mac Apple Silicon | `ai-security-runtime-v<version>-macos-arm64.tar.gz` |
| Mac Intel | `ai-security-runtime-v<version>-macos-x64.tar.gz` |

Download the archive and its `.sha256` file from the **same release**. For example, verify a published 0.3.8 Windows bundle in PowerShell:

```powershell
Get-FileHash .\ai-security-runtime-v0.3.8-windows-x64.zip -Algorithm SHA256
Get-Content .\ai-security-runtime-v0.3.8-windows-x64.zip.sha256
```

Compare the hashes, fully extract the archive, and keep the complete `security-check` directory. Follow [Codex](./guide/editors/codex.md#windows) or [Cursor](./guide/editors/cursor.md#windows) setup. The full bundle includes Python and does not require Node.js.

## Managed macOS installation

For Codex or Cursor, use the command on your [editor's setup page](./guide/quickstart.md#choose-editor). The installer detects Apple Silicon or Intel and prepares dedicated Python automatically. No preinstalled Python, Git, or Homebrew is required for installation.

The managed installer uses the separate [macos-trial-v0.3.9.2 release](https://github.com/pikachu-cxy/Ai-security-check/releases/tag/macos-trial-v0.3.9.2), with Runtime version 0.3.9. Keep its installation directory and verify its own build identity rather than comparing it to a native bundle's build ID.

## Manual macOS bundles {#macos-packages}

Choose the native archive for your chip from a published release. Download its matching `.sha256` file and verify before extracting. For a published 0.3.8 Apple Silicon bundle:

```sh
shasum -a 256 -c ai-security-runtime-v0.3.8-macos-arm64.tar.gz.sha256
```

Use `macos-x64` for Intel. Preserve the directory and executable permissions. Manual bundles and managed installation use different program paths. There is no Apple Developer ID signing or notarization guarantee; see [macOS troubleshooting](./reference/faq.md#macos-paste).

## After installation

Restart the editor, [verify the real connection](./guide/verify.md), and try the [isolated demo](./guide/demo.md). Matching checksums establishes content consistency, not that a project has passed a security check.

## Build and acceptance evidence {#build-details}

The current native release process runs regression, compliance, package-integrity, and platform-native acceptance checks before publishing assets. See [release Actions](https://github.com/pikachu-cxy/Ai-security-check/actions/workflows/release.yml). Read the selected release's `release-manifest.json` and `SHA256SUMS.txt` for actual source and artifact identities.

The [managed macOS workflow](https://github.com/pikachu-cxy/Ai-security-check/actions/workflows/macos-trial.yml) separately validates installation and build identity on both architectures. Isolated CI acceptance does not replace real desktop, first-download, signing, or scanner validation. See [support boundaries](./reference/support.md).
