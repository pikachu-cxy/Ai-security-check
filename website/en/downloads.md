# Downloads and installation

Current product: **0.3.9 Official release**, published on 2026-10-21. Native full bundles and managed macOS installation have separate release and build identities. Use the matching assets and checksums below.

## Official 0.3.9 full bundles {#windows}

The [v0.3.9 release](https://github.com/pikachu-cxy/Ai-security-check/releases/tag/v0.3.9) has published all three bundles and their companion checksums. They use source commit [`fa1a26b`](https://github.com/pikachu-cxy/Ai-security-check/commit/fa1a26bbc4db4eb8faae7281b689ec3205f10c26).

| Platform | Full bundle | Checksum |
| --- | --- | --- |
| Windows x64 | [Download](https://github.com/pikachu-cxy/Ai-security-check/releases/download/v0.3.9/ai-security-runtime-v0.3.9-windows-x64.zip) | [SHA256](https://github.com/pikachu-cxy/Ai-security-check/releases/download/v0.3.9/ai-security-runtime-v0.3.9-windows-x64.zip.sha256) |
| Mac Apple Silicon (M series) | [Download](https://github.com/pikachu-cxy/Ai-security-check/releases/download/v0.3.9/ai-security-runtime-v0.3.9-macos-arm64.tar.gz) | [SHA256](https://github.com/pikachu-cxy/Ai-security-check/releases/download/v0.3.9/ai-security-runtime-v0.3.9-macos-arm64.tar.gz.sha256) |
| Mac Intel | [Download](https://github.com/pikachu-cxy/Ai-security-check/releases/download/v0.3.9/ai-security-runtime-v0.3.9-macos-x64.tar.gz) | [SHA256](https://github.com/pikachu-cxy/Ai-security-check/releases/download/v0.3.9/ai-security-runtime-v0.3.9-macos-x64.tar.gz.sha256) |

Download the archive and its matching checksum from the same release. The full bundles include Python and require no separate Node.js installation.

```powershell
Get-FileHash .\ai-security-runtime-v0.3.9-windows-x64.zip -Algorithm SHA256
Get-Content .\ai-security-runtime-v0.3.9-windows-x64.zip.sha256
```

Compare the hashes, extract the complete archive, and retain the entire `security-check` directory. Follow [Codex](./guide/editors/codex.md#windows) or [Cursor](./guide/editors/cursor.md#windows) setup.

## Managed macOS installation

For Codex or Cursor, use the command on your [editor's setup page](./guide/quickstart.md#choose-editor). The installer detects Apple Silicon or Intel and prepares dedicated Python automatically. No preinstalled Python, Git, or Homebrew is required for installation.

The managed installer uses the separate [macos-trial-v0.3.9.3 release](https://github.com/pikachu-cxy/Ai-security-check/releases/tag/macos-trial-v0.3.9.3), with Runtime version 0.3.9. Keep its installation directory and verify its own build identity rather than comparing it to a native bundle's build ID.

## Manual macOS bundles {#macos-packages}

Choose the official archive for your chip from the table above. Download its matching `.sha256` file and verify before extracting. For a 0.3.9 Apple Silicon bundle:

```sh
shasum -a 256 -c ai-security-runtime-v0.3.9-macos-arm64.tar.gz.sha256
```

Use `macos-x64` for Intel. After verification, extract the archive and run `./security-check/security-check install codex` or `./security-check/security-check install cursor` from the extraction directory. Preserve the directory and executable permissions. Manual bundles and managed installation use different program paths. There is no Apple Developer ID signing or notarization guarantee; see [macOS troubleshooting](./reference/faq.md#macos-paste).

## After installation

Restart the editor, [verify the real connection](./guide/verify.md), and try the [isolated demo](./guide/demo.md). Matching checksums establishes content consistency, not that a project has passed a security check.

## Build and acceptance evidence {#build-details}

The [successful 0.3.9 release run](https://github.com/pikachu-cxy/Ai-security-check/actions/runs/39623506500) completed focused Windows/macOS regressions for the current changes, compliance, package-integrity, and native acceptance on all three platforms. It did not rerun the complete development suite. Read the matching `release-manifest.json` and `SHA256SUMS.txt` for source and artifact identities; do not use earlier candidate-build records.

The [managed macOS workflow](https://github.com/pikachu-cxy/Ai-security-check/actions/workflows/macos-trial.yml) separately validates installation and build identity on both architectures. Isolated CI acceptance does not replace real desktop, first-download, signing, or scanner validation. See [support boundaries](./reference/support.md).

[SHA256SUMS.txt](https://github.com/pikachu-cxy/Ai-security-check/releases/download/v0.3.9/SHA256SUMS.txt) · [release-manifest.json](https://github.com/pikachu-cxy/Ai-security-check/releases/download/v0.3.9/release-manifest.json) · [Acceptance evidence ZIP](https://github.com/pikachu-cxy/Ai-security-check/releases/download/v0.3.9/ai-security-runtime-v0.3.9-release-evidence.zip)
