# Preparation, installation options, and upgrades

For first-time installation, use the [Codex](./editors/codex.md) or [Cursor](./editors/cursor.md) page. This page covers status queries, manual preparation, and upgrades.

## Select the correct executable {#runtime-path}

| Installation | Executable |
| --- | --- |
| Windows full bundle | `.\security-check\security-check.exe` from the bundle's parent directory |
| Managed macOS installation | `"$HOME/.local/share/AI-Security-Runtime-macos-trial/security-check"` from any directory |
| Manual macOS full bundle | `./security-check/security-check` from the bundle's parent directory |

Do not mix paths from different installation methods. The examples below use the Windows bundle and managed macOS installation.

## Check preparation {#preparation}

::: code-group
```powershell [Windows]
.\security-check\security-check.exe preparation status
```
```sh [macOS]
"$HOME/.local/share/AI-Security-Runtime-macos-trial/security-check" preparation status
```
:::

Replace `status` with `watch` to observe progress. These are optional queries, not a second installation step. Initial engine, runtime, and vulnerability-data downloads depend on the network and existing cache. Keep the actual diagnostic for downloading, failed, or stale components.

## Inspect the build and connection {#connection-status}

::: code-group
```powershell [Windows]
.\security-check\security-check.exe runtime-info --json
.\security-check\security-check.exe status --json
```
```sh [macOS]
"$HOME/.local/share/AI-Security-Runtime-macos-trial/security-check" runtime-info --json
"$HOME/.local/share/AI-Security-Runtime-macos-trial/security-check" status --json
```
:::

Check `version`, `source_commit`, and `build_id` against the selected [release](../downloads.md#build-details). For Cursor, replace `status --json` with `integration status cursor --scope global --json`. These inspect configuration; [actual calls inside the restarted editor](./verify.md) establish whether it loaded the service.

## Full-bundle options

Options for `install codex` / `install cursor` include `--root <directory>`, `--bundle <directory>`, `--offline`, `--json`, and the source-development-only `--dev`. They are not arguments for the managed macOS shell installer, which accepts one editor name and uses a fixed product directory.

`--offline` checks existing local components and data; missing capabilities remain unavailable.

## Manual component preparation {#manual-preparation}

For manual MCP setup or a specific preparation diagnostic, use:

::: code-group
```powershell [Windows]
.\security-check\security-check.exe prepare-scanners
```
```sh [macOS]
"$HOME/.local/share/AI-Security-Runtime-macos-trial/security-check" prepare-scanners
```
:::

This prepares scanning engines and vulnerability data. It does not install business-project dependencies or start a project service. For a manual macOS bundle, use the corresponding executable from the path table.

## macOS startup {#macos-startup}

For paste warnings, read [the exact-message guidance](../reference/faq.md#macos-paste). For an unidentified-developer warning, verify the source and checksum and follow [Apple's app approval guidance](https://support.apple.com/en-us/102445). A Python shared-library or system-policy failure is distinct from a paste warning; retain its complete diagnostic.

There is no Developer ID signing or notarization guarantee. Do not disable system protection or TLS verification. A missing file calls for checking the executable path and extraction layout; changing executable permissions does not repair a signature or system-policy rejection.

## Upgrade or switch back

- **Managed macOS:** rerun your editor's documented installer, restart, and check the build. Reinstalling a pinned release does not imply a newer release exists. To switch back, run the original verified bundle's editor installer and verify the real connection before considering cleanup.
- **Manual bundles:** finish active checks, preserve configuration, download a new bundle and matching checksum, verify, and extract to a new directory. Install for the editor, handle reported conflicts, restart, and verify the actual build and workspace.

Do not overwrite a running program, delete user changes, or clear shared caches as a routine upgrade step. Pulling source does not upgrade a separately installed product. Source development instructions are in the [repository README](https://github.com/pikachu-cxy/Ai-security-check#develop-from-source).
