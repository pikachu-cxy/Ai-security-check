# Preparation, installation options, and upgrades

For the **0.3.9 official release**, use the [Codex](./editors/codex.md) or [Cursor](./editors/cursor.md) page to install. Managed macOS uses **macos-trial-v0.3.10**. This page covers status queries, component preparation, upgrades, and removal.

## Select the correct executable {#runtime-path}

| Installation | Executable |
| --- | --- |
| Windows full bundle | `.\security-check\security-check.exe` from the bundle's parent directory |
| Managed macOS installation | `"$HOME/.local/share/AI-Security-Runtime-macos-trial/security-check"` from any directory |
| Manual macOS full bundle | `./security-check/security-check` from the bundle's parent directory |

Do not mix paths from different installation methods. The examples below use the Windows bundle and managed macOS installation.

Windows full-bundle installation defaults to version slots under `%LOCALAPPDATA%\AI-Security-Runtime-install`. Check the executable actually loaded by the editor; do not use Python from an old development checkout to verify the new installation.

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

### Inspect components without downloading

```powershell
.\security-check\security-check.exe prepare-scanners --status --json
```

Use your installation's executable path on macOS. `--status` does not download. Check code, secret, and dependency engines separately, along with vulnerability-data validity. `READY` and an accepted workspace establish preparation, not a passing project check. `NEEDS_SCAN` means no scan has been recorded.

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

Version 0.3.9 distinguishes missing tools, unverifiable execution identity, missing local OSV databases, expired data, and an unknown update time. Prepare missing components online or follow the specific data diagnostic, then retry. Installing OSV alone does not populate its local databases. Online preparation may create independent managed Semgrep for an unverified auto-discovered system tool; explicitly chosen paths and broken managed installations keep their diagnostics. Initial macOS Semgrep validation has a longer cold-start allowance within the overall preparation budget; ordinary status probes remain bounded.

## macOS startup {#macos-startup}

For paste warnings, read [the exact-message guidance](../reference/faq.md#macos-paste). For an unidentified-developer warning, verify the source and checksum and follow [Apple's app approval guidance](https://support.apple.com/en-us/102445). A Python shared-library or system-policy failure is distinct from a paste warning; retain its complete diagnostic.

There is no Developer ID signing or notarization guarantee. Do not disable system protection or TLS verification. A missing file calls for checking the executable path and extraction layout; changing executable permissions does not repair a signature or system-policy rejection.

## Upgrade or switch back

- **Managed macOS:** rerun your editor's documented installer, restart, and check the build. Reinstalling a pinned release does not imply a newer release exists. To switch back, run the original verified bundle's editor installer and verify the real connection before considering cleanup.
- **Manual bundles:** finish active checks, preserve configuration, download a new bundle and matching checksum, verify, and extract to a new directory. Install for the editor, handle reported conflicts, restart, and verify the actual build and workspace.

Do not overwrite a running program, delete user changes, or clear shared caches as a routine upgrade step. Pulling source does not upgrade a separately installed product. Source development instructions are in the [repository README](https://github.com/pikachu-cxy/Ai-security-check#develop-from-source).

## Uninstall and reinstall {#uninstall}

Finish active checks, completely quit the affected editor, and use the original installed executable or verified bundle in a separate terminal. From the Windows bundle's parent directory, run only the command for the editor you want to remove:

```powershell
# Codex product integration
.\security-check\security-check.exe uninstall --json

# Or: Cursor user-level product integration
.\security-check\security-check.exe integration remove cursor --scope global --json
```

On macOS, substitute the correct executable from the path table. The companion Skill can be shared by multiple hosts. Only remove it after no remaining integration needs it:

```powershell
.\security-check\security-check.exe review-skill remove --json
```

Removal affects provably owned product entries, preserving unrelated services and user changes. Retain ownership or configuration-conflict diagnostics. It does not clear program slots, caches, or scan history. For manual MCP setup, remove only the service entry you added. Do not delete the entire editor configuration or project source.

Reinstall with the verified [current download](../downloads.md) and the editor's installation command, or use its managed macOS installer. Restart and verify the actual executable, build, components, and project root. Routine upgrades do not require uninstalling first.
