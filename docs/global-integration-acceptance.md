# Core P0-7 — Global Runtime Integration / Install Once

This report distinguishes official support, local evidence and Desktop gates.
No real user Codex configuration, active Runtime, Git history or remote was
changed. The starting branch is `feature/runtime-mvp`, HEAD
`ee1bfd9c12493683cc313cb3628753a51ae124ac`; all earlier dirty work is retained.

## Official behavior and locally observed behavior

| Property | Official contract | Local evidence / remaining gate |
| --- | --- | --- |
| User Hooks | `$CODEX_HOME/hooks.json`, next to active user config | Generated isolated fixture uses the three existing definitions |
| User MCP | `[mcp_servers.ai_security_runtime]` in user config | Codex CLI 0.159.2 `mcp list/get --json` reads it from temporary CODEX_HOME |
| Hook trust | Exact current definition hash; changed definition needs review | Stable definition fingerprint across A/B; actual Desktop trust reuse Pending |
| Project trust | Gates project-local layers; user Hooks can still load | No Runtime project-trust decision, override or trust-store modification |
| Merge | Matching user/project Hooks accumulate | Owned project migration removes all three old Runtime events; unknown related Hooks conflict |
| Event cwd | Common Hook input supplies cwd | Actual MCP fixture passes A/src and B/src for SessionStart/PostToolUse/Stop |
| MCP readiness | MCP Hook uses an already connected server; SessionStart can precede readiness | First PostToolUse without completed baseline returns INITIALIZING/inconclusive |

Sources actually consulted:
[Hooks](https://learn.chatgpt.com/docs/hooks),
[MCP](https://learn.chatgpt.com/docs/extend/mcp),
[advanced config](https://learn.chatgpt.com/docs/config-file/config-advanced),
[CODEX_HOME](https://learn.chatgpt.com/docs/config-file/environment-variables).
Public CLI configuration inspection does **not** prove Hook delivery or trust
approval. No private Codex database was read or changed.

## Architecture and scope

- GlobalCodexIntegration reuses the existing signed manifest/fingerprint merge,
  duplicate detection, bounded parsers, compare-before-write and rollback.
  Only destinations and launch scope change. User TOML outside the managed block
  remains byte-for-byte. Unrelated JSON values/handlers remain; JSON formatting
  can change on an actual merge. No-change setup/repair preserves bytes and mtime.
- User-level Hook definitions are unchanged `product_hooks()`: SessionStart,
  PostToolUse and Stop, MCP transport, `${cwd}` and existing claim schemas.
  Ownership is not enterprise policy trust and does not grant Codex approval.
- Installed Python `-I -m security_runtime.cli mcp` or frozen launcher is stable
  across projects. Config contains no repository source/PYTHONPATH path and no
  fixed project cwd. DEV requires explicit acknowledgement and still must pass
  a real CLI + MCP global capability handshake; the same 0.3.1 version alone is
  insufficient. No updater, atomic switching or rollback infrastructure.
- GlobalWorkspaces creates a normal workspace-bound MCP server, HookCoordinator
  and remediation service per canonical root. Separate DB, Hook state/key,
  baseline, receipts, Family/Episode and live tickets/triage handoffs. Existing
  scanner static caches retain their safe process-level lifetime; scanner
  results/proofs are not cached or shared.
- Root admission rejects home/drive/system/state/config roots, UNC, traversal,
  unresolved templates, symlinks/junctions including ancestors. Git subdirectories
  resolve to the nearest repository, including nested Git repositories. Non-Git
  projects use bounded name-only layout recognition, then bounded source
  snapshots. No disk-wide or home-wide project search.
- Global connections route only by explicit `workspace_path` (or an existing
  explicit scan path alias). Even one admitted root is not evidence of Host's
  current workspace. They never decode a reference to select a workspace and
  never use a last-workspace variable. Global-only schemas add workspace_path
  to reference-only tools; global dispatch requires it for every request. Existing project
  schemas, opaque values and Core proof/receipt checks remain unchanged.
- A session claim cannot switch roots. Connection budgets are 16 roots / 64
  sessions; they fail closed rather than evict another root's live authorization.
- SessionStart initializes a bounded quick SAST/Secret comparison baseline in a
  two-thread in-process executor. It reuses the existing tracked/untracked source
  inventory, coverage checks and source byte recheck, then publishes under the
  same workspace lock. Budgets reject an oversized inventory. Existing clean-file
  risks must be PERSISTING, not NEW on an unrelated edit. Ordinary edits remain
  incremental; initialization never calls the Full Scan API or build/test.
  Only hashes and safe Hook projections survive the initial baseline scan;
  initial source/Finding packets are not stored in the workspace DB. No daemon
  or persistent Scanner process is added.
- Bootstrap reports NEW_WORKSPACE → INITIALIZING → READY, or DEGRADED/ERROR.
  READY is a comparison/readiness observation, never a safety verdict. Runtime
  reconnect creates new live contexts; old prepared tickets are not restored.
  If startup Hook was skipped or initialization failed, an edit cannot claim
  NEW attribution or AUTO_FIX based on a fabricated baseline.
- Non-Git source projects are supported for bounded advisory Hook checks. Their
  source inventory is bounded; it is not a Git dirty-file diff. Git-dependent
  remediation authorization is not upgraded to non-Git AUTO_FIX. This limit is
  explicit rather than fabricating a stronger proof.
- Core remains incremental scan → policy → necessary AUTO_FIX → real targeted
  security recheck → return. Deep APIs remain compatible and explicitly requested;
  no Functional/build/Sandbox operation is added to default Hooks.
- Explicit manual MCP scans retain the existing full ScannerRegistry; the Core
  registry is confined to Hook scans and comparison baselines.

## Ownership, migration and CLI

RUNTIME_MANAGED_GLOBAL and RUNTIME_MANAGED_LEGACY_PROJECT require exact signed
ownership. Other unrelated config is USER_MANAGED. Unproven related config is
UNKNOWN and conflicts; same names or status messages never authorize deletion.

Setup/repair checks only the current workspace's active root-to-cwd `.codex`
layers. It migrates proven project Runtime entries and preserves mixed user
groups. It does not enumerate unrelated repositories. A newly encountered old
project can return LEGACY_PROJECT_CONFIGURATION_REQUIRES_REPAIR; explicit repair
for that project is required. Unknown entries remain for user resolution. An
existing child does not hide a newly added duplicate at a subdirectory layer.
Unknown Runtime launcher aliases and related Hook aliases conflict without
deletion. Legacy security history remains in its previous namespace. Configuration
migration does not copy historical receipts/grants or reinterpret old opaque refs;
request a fresh current-workspace result if a legacy ref is stale.

Default commands: `security-check setup`, `status`, `doctor`, `repair`,
`uninstall`. `--path` on status/repair inspects or migrates only that workspace.
Legacy `setup codex --path ...`, `setup --scope project`, `integration ... codex`
and explicit project scanner doctor remain. Bare doctor now means global
integration; `doctor --project` keeps the old scanner/project behavior.
`setup --scope global --path ...` explicitly migrates from a specified workspace.
Uninstall only removes owned global entries; it leaves workspace security
history and unrelated user/project configuration.

## Automated evidence

Changes relative to the preserved P0-7 incoming workspace:

| Category | Files |
| --- | --- |
| New product modules | `src/security_runtime/global_integration.py`, `global_workspace.py`, `global_mcp.py` |
| Existing product modules | `src/security_runtime/baseline_seed.py`, `cli.py`, `codex_integration.py`, `hook_runtime.py`, `mcp_server.py`, `runtime.py` |
| Tests | New `tests/test_global_integration.py`; `tests/test_doctor.py` explicitly selects legacy project doctor |
| Acceptance/package | `scripts/global_integration_acceptance.py`, `MANIFEST.in` |
| Existing documentation | `docs/PROJECT_STATE.md`, `ARCHITECTURE.md`, `DECISIONS.md`, `NEXT_STAGE.md`, `AI_TRIAGE_ACCEPTANCE.md` (previous contents retained) |
| New documentation/evidence | This report, `global-integration-design.md`, `global-integration-package.json`, `global-integration-sdk-final.json`, `global-integration-regression.json`, `global-integration-workspace-audit.json`; initial SDK reports are historical evidence |

The incoming audit covers 414 files without deletions. All changes to existing
product files are the reviewed P0-7 hunks; unrelated earlier dirty work remains.
`docs/PROJECT_CONTEXT.md` is excluded and was not read or written.

| Gate | Current completed evidence |
| --- | --- |
| Focused | 253 passed, 290.34s; 64 new global integration cases |
| Baseline review | 94 passed, 88.07s |
| Full offline | 1389 passed, 9 skipped, 6 subtests passed, 1821.36s (30:21); final explicit-routing source |
| wheel/sdist integrity | PASS; all 78 Runtime Python files byte-matched |
| Compliance | Distribution licenses and generated notices PASS |
| Installed wheel SDK trial | PASS, 119.99s, final explicit-routing wheel and actual offline Semgrep/Gitleaks |

See [package](global-integration-package.json),
[SDK evidence](global-integration-sdk-final.json), and
[incoming workspace preservation audit](global-integration-workspace-audit.json).
The [final regression report](global-integration-regression.json) records skips
separately: three opt-in managed performance tests and six legacy E2E cases that
require real scanner binaries on their explicit test path. Those six are not
claimed PASS by the separate managed Semgrep/Gitleaks SDK trial. Interrupted review runs
are not passes. An added SQLite assertion initially left the acceptance script's
own connection open, causing Windows temporary cleanup to fail; explicit close
fixed that fixture and the final SDK trial passed including cleanup.

The first completed full run (1388 passed / 9 skipped / 6 subtests, 1958.99s)
preceded the explicit-claim hardening; it is historical evidence, not the final
gate. Final product/test/acceptance script hashes remained unchanged throughout
the final full run. One dependency lifespan-forward-reference warning appeared
in the focused run; there were no test failures. The five existing documents
retain their incoming contents below the new P0-7 handoff.

The isolated SDK trial uses an installed wheel in a temporary venv with existing
dependencies (`--no-index --no-deps --system-site-packages`), temporary CODEX_HOME,
actual MCP and real managed offline Semgrep/Gitleaks. The simulated Host edits
only disposable Java fixtures. It is not a clean third-party dependency install
or a Desktop trial. No model call, network query, build or raw opaque-reference
serialization.

The installed trial proves fresh/repeated setup, owned legacy migration,
status/doctor/healthy repair/uninstall and user config preservation. Public Codex
CLI 0.159.2 discovers the global MCP. One actual stdio connection handles A1, B1
and A2 recurrence with unchanged original refs; all close using real scanner
proof, zero prepare calls and ALLOW_STOP. Cross-workspace refs and ambiguous
requests are rejected, including a missing workspace claim with only A admitted
before B's first Hook. Initial baseline databases contain no scan/Finding
packets. No project config is generated for A or B. The Runtime module origin is
asserted to be the temporary venv, not a same-version base installation.

## User-run Desktop gate

After the user deliberately loads the new delivered Runtime:

1. Run `security-check setup` once; review the user-level three Hooks in Codex
   using the supported Hook review UI / `/hooks`, then reconnect/restart.
2. Open clean Git Project A. Confirm SessionStart converges to READY; no project
   `.codex` is created. A safe edit must finish without a fabricated security
   proof or automatic Deep Verification.
3. Open clean Git Project B without setup. Check whether the same global Hook
   requires another review. Confirm B's separate workspace readiness/state.
4. In a disposable fixture introduce the known TLS line; observe INLINE_PREPARED,
   one bounded edit, real security recheck, resolved/CLOSED/RETURN_TO_HOST.
5. Check user-level MCP/Hook definitions remain unchanged between A/B. Exercise
   an owned old project with `security-check repair --path <old-project>`; unknown
   config must remain and report a conflict.
6. Repeat setup/repair, inspect status/doctor, then uninstall; user settings and
   other MCP/Hooks must remain.

Trust-once and actual first-open protection are **PENDING_ACTUAL_DESKTOP** until
the user completes that gate. A stable fixture definition hash is not a forged
trust observation. Source-only tests do not replace the active Runtime.

Current bootstrap limits: Git inventories keep the existing 1,000-file / 20 MB
budget and full quick-capability comparison requirement. An oversized, moving,
failed or partial initial baseline stays DEGRADED and cannot authorize AUTO_FIX.
The current connection retains that initialization outcome; after addressing
the prerequisite, reconnect with a new session to initialize again. A first edit
that arrives before baseline readiness is inconclusive, not an attributed NEW
risk. Non-Git checks remain advisory. These limits qualify the install-once
claim; readiness is never evidence of universal language coverage or project
safety.

Previous P0-6/P0-6.1 real Desktop closure is now
USER_REPORTED_ACTUAL_DESKTOP_PASS based on the new user report (prepare=0,
read=1, search=0, exact envelope MATCHED/outside=false, cycle≈65.9s,
Host/Agent window≈51.6s). This round does not rerun or optimize that trial.
Three independent users remain Pending, Ground Truth UNREVIEWED/null, Maven
PENDING_ENVIRONMENT_PREREQUISITES. No other phase is started.
