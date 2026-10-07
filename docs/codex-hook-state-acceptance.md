# Core P0-7.1 — Codex hooks.state compatibility acceptance

Scope: narrow compatibility only. HEAD ee1bfd9c12493683cc313cb3628753a51ae124ac / feature/runtime-mvp. No commit/push/active Runtime replacement or real user config access.

## Official schema and sources

Checked 2026-10-06: [official config schema](https://learn.chatgpt.com/docs/config-schema.json), definitions HooksToml / HookStateToml / HookHandlerConfig / MatcherGroup. TOML state maps opaque keys to objects, with optional boolean enabled and string trusted_hash. Additional state entry fields are not forbidden by that schema and remain host-owned. Runtime allows only this named metadata branch; arbitrary dictionary-valued hooks keys are not accepted.

[Official Hooks documentation](https://learn.chatgpt.com/docs/hooks) describes loading both hooks.json and inline TOML event definitions additively, warning when both contain hook definitions in the same layer. Runtime keeps the existing two sources and conflict checks, excluding only state from event iteration. It neither claims nor edits Codex trust state. Real Codex CLI config parsing with state plus generated hooks.json succeeds in the isolated trial; actual Desktop trust/discovery remains outside this test.

## Reproduction and preservation

Sanitized fixture only: tests/fixtures/codex/host-hook-state.toml, plus node_repl and unrelated synthetic config. No real user values copied. Before fix the same valid TOML structure reports CONFIG_INVALID; after fix setup reports CONFIGURED with MCP/Hook CONFIGURED. The initial before/after reproduction uses a deterministic capability probe. The separate installed trial uses the real installed CLI and MCP capability handshake, and public Codex CLI 0.159.2 mcp list confirms both MCP entries.

25 new cases cover state-only, state+node_repl/unrelated settings, state+user inline hooks, existing Runtime hooks, repeated setup/repair with bytes+mtime unchanged, uninstall restoring exact original bytes, mixed JSON and inline user hooks, project-layer state, unknown malformed metadata rejection, official state extensions preservation, malformed Runtime-owned hooks rejection, inline Runtime conflict, JSON state rejection, and immutable parsed document view.

## Results

- Focused: 160 passed / 121.85s.
- Full offline: 1414 passed, 9 skipped, 6 subtests passed in 1853.57s (0:30:53); runner 1854.15s.
- Skips: 3 opt-in managed performance cases, 6 prior real E2E binary prerequisites. They remain skipped, not PASS.
- Wheel/sdist integrity and licenses/notices compliance: PASS. First packaging attempt exposed missing TOML fixture in sdist; fixed only MANIFEST include and reran successfully.
- Temporary installed lifecycle: PASS / 25.22s; forced wheel install in disposable venv uses existing dependency environment with --no-index/--no-deps/--system-site-packages. Not a fully empty dependency installation.
- Actual Codex CLI config parse and MCP discovery: PASS. Actual Desktop Hook trial: NOT_RUN/PENDING.
- Pre-existing dirty source outside two narrow integration modules: byte-preserved. No Global architecture/router/remediation/Ticket/Scanner/Functional/CET changes.

Reports: [regression](codex-hook-state-regression.json), [installed trial](codex-hook-state-installed-trial.json), [package](codex-hook-state-package.json), [workspace audit](codex-hook-state-workspace-audit.json).

## User retry after loading the fixed Runtime version

```powershell
security-check setup --scope global
security-check status --json
security-check doctor --json
```

If an existing owned partial installation needs repair: security-check repair --json. No need to remove host-owned hooks.state or unrelated MCP entries. This development task has not changed the active installed Runtime; running its old executable still uses the old parser. Desktop reload/reconnect and normal hook trust review remain user-controlled.
