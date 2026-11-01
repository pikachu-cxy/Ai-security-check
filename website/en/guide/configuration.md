# Custom configuration

Version 0.3.12 introduces one user-owned TOML file for capacities, agent analysis, Stop fallback, scan rules and vulnerability data. Omitted fields keep their defaults. Upgrades preserve your file.

## Locate, edit and verify

| System | Default path |
| --- | --- |
| macOS / Linux | `~/.config/ai-security-runtime/config.toml`, respecting `XDG_CONFIG_HOME` |
| Windows | `%APPDATA%\ai-security-runtime\config.toml` |

`SECURITY_RUNTIME_CONFIG` can select another absolute path when passed to the Runtime's startup environment. Project-local settings are not loaded automatically. Use a regular UTF-8 file, not a symbolic link; maximum size is 64 KiB.

Run `security-check development-config` to see the actual path, source and values. For managed macOS installation:

```sh
RUNTIME="$HOME/.local/share/AI-Security-Runtime-macos-trial/security-check"
"$RUNTIME" development-config
mkdir -p "$HOME/.config/ai-security-runtime"
```

For native bundles, use your installed executable, `security-check.exe` on Windows. See [program paths](./installation.md#runtime-path). Back up an existing file and edit its existing tables; do not append duplicate TOML tables. Download the <a href="../../examples/config.toml" download>complete default example</a>, or start with only the fields you need.

## Development checks and Stop

```toml
schema_version = 1

[storage]
development_record_limit_enabled = true
development_max_records = 1024

[agent]
review_scanner_findings = true
audit_business_logic = true

[development.stop_fallback]
enabled = true
wait_timeout_seconds = 120
max_continuations = 2
```

The 1024 quota controls admission of new development records per workspace, not file count. Existing records remain readable and can finish above the quota; history is not automatically deleted. Set `development_record_limit_enabled=false` to remove this quota. `development_max_records` must stay positive; independent database and per-record protections remain.

Agent finding review and business-logic audit default to enabled and can be disabled independently. Stop defaults to enabled; its total budget accepts 1–3600 seconds and its continuation cap accepts 1–10. Host limits may be lower. Disabling Stop does not disable normal agent closeout.

### Static-only checks with Stop enabled

Change the corresponding existing tables to:

```toml
[agent]
review_scanner_findings = false
audit_business_logic = false

[development.stop_fallback]
enabled = true
wait_timeout_seconds = 120
max_continuations = 2
```

The agent reports static candidates without submitting an agent review or claiming confirmation. Both optional agent analyses are themselves static code analysis, not execution of your application.

Stop handles recorded edits in the current turn and their continuation, keeping the original check. It does not resume old checks during read-only chat or resubmit queued scans. Failures and exhausted budgets remain incomplete. Cancellation, missing host events and unobserved writes cannot be reliably recovered. Reading a result does not prove the user received it.

## Project capacities and execution budgets

Values below are nonnegative integers. **0 disables only that individual cap.** Other stages still have their own limits. Bytes are decimal integers and time is in seconds.

| Table | Default fields | Scope |
| --- | --- | --- |
| `[scan.discovery]` | `max_files=10000`, `max_directories=2000`, `max_depth=32`, `max_file_bytes=1000000` | File discovery |
| `[scan.input]` | `max_files=10000`, `max_total_bytes=128000000`, `max_file_bytes=4000000`, `max_index_bytes=8000000` | Fixed scan input and index |
| `[scan.git]` | `timeout_seconds=10`, `max_output_bytes=4000000` | Git queries |
| `[scan.execution]` | `sast_timeout_seconds=45`, `gitleaks_timeout_seconds=30`, `trivy_timeout_seconds=90`, `max_output_bytes=4000000` | Scanner execution |
| `[scan.dataflow]` | `max_files=256`, `max_total_bytes=8000000`, `max_file_bytes=500000`, `max_steps=1000000`, `max_depth=6`, `feature_timeout_seconds=3`, `release_timeout_seconds=30` | Built-in bounded dataflow |
| `[storage.explicit_scan_jobs]` | `max_records=128`, `max_total_bytes=96000000`, `max_database_bytes=128000000` | Explicit scan job storage |
| `[storage.scan_publication]` | `max_records=32`, `max_record_bytes=8000000`, `max_total_bytes=32000000` | Published scan result storage |

For example, remove file-count limits in discovery and fixed input:

```toml
[scan.discovery]
max_files = 0

[scan.input]
max_files = 0
```

File-size, directory, engine and dataflow limits still apply. Follow the diagnostic's exact configuration section and submit a new scan after changing it. A limit failure is not a clean scan. Lowering storage quotas does not delete history.

The zero rule does not apply to `development_max_records`, Stop time/count or database refresh interval. Physical memory, disk and engine constraints remain; cancellation, ownership, version checks, no-link checks and pagination are preserved.

## Custom scanning rules

```toml
[rules.sast]
mode = "extend"
paths = ["/absolute/path/to/my-rules"]
exclude_ids = []
```

`builtin` uses bundled rules and requires empty paths. `extend` adds local rules. `replace` uses only your code-scanner rules; it does not disable independent scanners or built-in dataflow. Use absolute local directories containing native scanner YAML, for example:

```yaml
rules:
  - id: local.eval-candidate
    languages: [python]
    message: Review dynamic evaluation of this expression
    severity: ERROR
    pattern: eval($X)
```

Exclude exact executed rule IDs. Unknown IDs, duplicate IDs, invalid paths or YAML produce errors instead of silent default fallback. Rule validation retains its own 10000-YAML-file and 1 MB-per-file bounds. Custom rules conservatively bypass old scan-result reuse. Windows TOML literal strings avoid backslash escaping: `paths = ['C:\security-rules']`. Do not use `~` as an absolute path.

For secrets, set `[rules.gitleaks] config_path="/absolute/path/to/gitleaks.toml"`. Empty preserves existing behavior. Use native Gitleaks TOML; include `[extend]` with `useDefault=true` in that file to retain its default rules. Scanning uses a validated fixed copy.

## Vulnerability data

```toml
[vulnerability_data.trivy]
repositories = []
cache_dir = ""
update_mode = "auto"
update_interval_seconds = 0
stale_policy = "allow_with_gap"
```

- `repositories`: public OCI database repositories in `registry/path:tag` form. Empty uses bundled defaults. No URL scheme, credentials or query parameters.
- `cache_dir`: absolute local directory; empty retains the current environment/default location.
- `update_mode`: `auto` uses automatic preparation policy; `manual` allows explicit updates only; `offline` blocks even explicit updates.
- `update_interval_seconds`: 0 follows upstream expiry; a positive age also requests refresh. Zero does not mean never expires.
- `stale_policy`: `allow_with_gap` may retain old data and report a gap; `require_fresh` prevents expired data from completing dependency vulnerability checks.

```sh
security-check vulnerability-data status --json
# Requires networking; rejected in offline mode
security-check vulnerability-data update --json
```

Update failure preserves usable old data. Ordinary local development rechecks do not download merely because auto is selected. This configures Trivy-supported database sources, not arbitrary JSON/CSV vulnerability lists or new Rego policies. Program, rule and data versions are separate.

## When changes apply

Save and run `security-check development-config`; check `VALID` and the effective values. The command is read-only, not an Apply button. TOML changes need no restart or reinstallation. Existing batches and submitted background scans retain their saved settings; use a new check and real new edits to test a new combination.

Unknown keys, wrong types, duplicate tables and invalid values produce `INVALID`. Fix the error or restore your backup; do not remove check databases. Removing a custom field restores its default.

Explicit operation arguments take priority, then explicitly supplied unified settings, legacy environment settings, legacy `scan-limits.toml`, and defaults. Configuration participates in project-result reuse identity. Fast status queries do not revalidate component health.

Codex CLI and Cursor CLI require native Hook support and enabled events. Claude Code and Qoder CLI remain planned. See [daily workflow](./workflow.md) and [platform support](../reference/support.md).
