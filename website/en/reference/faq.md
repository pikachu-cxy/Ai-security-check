# Troubleshooting

## Why does Cursor still ask me to Run a tool?

Cursor controls execution approval. Full installation maintains an exact routine MCP allowlist, but run mode, `~/.cursor/permissions.json`, and team policy may still require confirmation. Command and MCP allowlists are separate. Reinstall the integration from the current verified bundle and restart, preserving user policy.

## User accounts and chat binding

Local configuration and history belong to the operating-system user. Another OS account or computer normally needs its own integration; records do not sync automatically. Changing only an editor login does not necessarily remove local settings. Verify the real connection.

Chat ownership keeps checks and decisions associated with the correct workspace and conversation. Hooks provide credentials; users do not enter them. After reconnecting, read the original check rather than creating a replacement.

## Why are risk statistics empty?

Select Codex, Cursor, or all editors in 0.3.11. Check the actual build, OS user, filters, and read diagnostics. The page reads saved local records; other devices, accounts, or custom legacy directories are not automatically combined. Cross-editor duplicates remain separate. See [risk statistics](../guide/risk-handling.md).

## Installation ended; is the project checked?

No. Installation, component preparation, editor connection, and actual project review are separate states. [Verify the real connection](../guide/verify.md), then try the [isolated demo](../guide/demo.md).

## Components are still downloading

Use the [preparation status](../guide/installation.md#preparation) command for your installation method. Keep the actual component, state, and diagnostic. Installation already starts preparation; repeatedly reinstalling or clearing caches is not a substitute for diagnosis.

## The editor still shows an older version

Completely quit old processes and reopen the editor. Check the actual executable, `version`, `source_commit`, and `build_id` against the selected release. Pulling source does not upgrade a separate installed Runtime. An updated Skill cannot add a missing engine capability.

## macOS blocks pasting a command {#macos-paste}

Read the exact message. A warning about pasting potentially unsafe text is an execution-before-paste protection and does not by itself establish that this installer was detected as malware or already ran. Verify you copied only the documented command, with the expected `https://pikachu-cxy.github.io/Ai-security-check/install/macos.sh` address and correct editor argument.

The command downloads and executes an installer, prepares a dedicated environment, and configures the chosen editor. Continue only if you trust the source, understand the action, and intend to install. If unsure, decline. Do not disable system protection. If the message specifically reports detected malware or a blocked malicious script, stop and retain the diagnostic rather than treating it as an ordinary paste warning.

See [Apple's guidance](https://support.apple.com/en-us/127377). A launch-time developer-verification or Python-library rejection is a different issue; see [startup troubleshooting](../guide/installation.md#macos-startup). There is no signing or notarization guarantee.

## The executable cannot be found

For full bundles, check that extraction is complete and the terminal is in the parent of `security-check`. For managed macOS setup, use `"$HOME/.local/share/AI-Security-Runtime-macos-trial/security-check"`; do not assume it was added to PATH. See [program paths](../guide/installation.md#runtime-path).

## The check is incomplete or shows zero findings

Read actual coverage and limitations. Missing components, stale data, file limits, unreadable source, and missing pre-edit evidence are different causes. Incomplete does not mean a vulnerability was found; zero findings does not prove security or remediation of an earlier issue. See [the workflow](../guide/workflow.md).

## NEEDS_SCAN or a rejected project path

`NEEDS_SCAN` means no scan has been recorded. If components are `READY` and the actual source root is accepted, installation is usable; request a scan when needed. There is no need to reinstall to clear that state.

For a rejected path, first confirm that the editor opened the source and Git repository root rather than an outer extraction folder. Supply that absolute root explicitly in a read-only status query. A rejection code alone does not identify the cause. Keep the returned diagnostic if it persists; see [verification](../guide/verify.md).

## A tool reports its version but is not ready

A version string does not establish a valid executable or data set. Check OpenGrep, Gitleaks, and Trivy identities and the applicable vulnerability data. Trivy failure reports a dependency gap; it does not automatically switch to OSV. Follow [preparation](../guide/installation.md#manual-preparation) using the specific diagnostic.

## Uninstall before reinstalling

Quit the editor and use the product's owned-integration removal command. Remove the shared Skill only when other hosts no longer need it. Program slots, caches, and history remain; routine upgrades do not require clearing them. Follow [removal and reinstallation](../guide/installation.md#uninstall), preserving unrelated editor settings and source.

## Are all code and logs local?

The Runtime and scanners run locally, but the host agent follows its own data policies. Review records can contain code snapshots. Optional usage-monitoring records have a different data scope. See [privacy](./privacy.md).

## Report a problem {#report}

Open a [GitHub issue](https://github.com/pikachu-cxy/Ai-security-check/issues) with:

- OS and architecture, editor version, and installation method.
- Actual Runtime version, source commit, and build ID.
- Failure stage and minimal reproduction steps.
- Necessary sanitized diagnostic and affected component.

Do not attach credentials, raw chats, private source snapshots, or whole runtime databases. Separate what happened from what remains unverified.
