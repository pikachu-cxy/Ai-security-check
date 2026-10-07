# Core P0-7 design and acceptance boundaries

User-level Codex config and hooks are the default installation target. Runtime
ownership does not confer Codex trust. The three released MCP hook definitions
remain unchanged and obtain workspace claims from `${cwd}`. Matching user and
project hooks accumulate; a project layer cannot suppress a duplicate by
precedence. Official sources: [Hooks](https://learn.chatgpt.com/docs/hooks),
[MCP](https://learn.chatgpt.com/docs/extend/mcp),
[configuration](https://learn.chatgpt.com/docs/config-file/config-advanced).

Global integration reuses the project installer's signed ownership, exact
fingerprint matching, bounded parsers, compare-before-write and rollback. A small
subclass changes destinations and the stdio launch environment; it does not
rewrite all TOML. The launcher is an installed interpreter/module or frozen
executable, not a repository source path. Source-only execution is explicitly
DEV and requires an explicit development opt-in.

Global MCP is a transport router around existing workspace-bound servers. Each
canonical workspace has its own store, HookCoordinator, remediation service,
opaque handoffs and live tickets. Ref values are passed unchanged. Routing never
uses a decoded ref, a sole-admitted-root default or a mutable last-workspace
pointer. Every global workspace request must supply `workspace_path` (or the
existing explicit scan path alias), even with only one root admitted: Host could
already have moved to a not-yet-admitted project. Global-only schemas add the
claim to tools that previously had none. Existing project MCP schemas remain
unchanged. A session claim cannot switch roots, and connection budgets do not
evict another workspace's live authority.

SessionStart submits a bounded initial quick-scope baseline to a two-thread
in-process executor. NEW_WORKSPACE / INITIALIZING is not READY and is not scanner
proof. Git initialization reuses WorkspaceBaselineSeeds' bounded tracked/untracked
source inventory, SAST/Secret coverage checks, byte recheck and projection-only
storage. Publication into the actual session occurs under the same workspace
lock. Otherwise a pre-existing clean-file risk could be misclassified as NEW
after an unrelated edit. Ordinary edits retain the existing incremental scope;
initialization does not invoke the Full Scan API or Deep Verification.
PostToolUse during initialization returns an inconclusive advisory. If
SessionStart was skipped before MCP connection readiness, the first edit starts
initialization and is not attributed as NEW or automatically fixed. The next
event can converge. There is no daemon, build or Functional Verification.

Git snapshots retain their existing implementation. Non-Git source directories
use a bounded, keyed inventory snapshot; ambiguous directories and links are
rejected. Non-Git Core checks remain bounded and advisory; Git-dependent
remediation proof is not upgraded by global discovery. State and CODEX_HOME are
excluded from valid scan targets. Empty directories, drives, home and system
directories are never implicitly accepted as projects.

Migration examines only the current workspace's active `.codex` layers, not the
disk. Proven legacy project installs can be removed by setup/repair. Unknown or
user-owned related entries remain and produce a conflict. A previously unknown
legacy project encountered later returns DEGRADED until explicit repair; no
unowned config is deleted silently. Global uninstall removes its own config only.
Renamed Runtime launchers and Hook server aliases are relatedness diagnostics,
never evidence of ownership. Legacy security records remain in their original
namespace; migration does not reinterpret old refs or copy grants into the new
workspace namespace. Old refs may require a fresh current-workspace result.

Explicit manual MCP scans keep the existing full ScannerRegistry. Only Core
Hooks and initial comparison baselines use the SAST/Secret registry. There is
no change to explicit Deep API availability or the released risk policy.

Local tests can prove config discovery with temporary CODEX_HOME, stable hook
definition hashes and workspace isolation. They cannot prove Desktop trust UI,
cross-project approval reuse or actual event delivery. These remain a user-run
Desktop gate; no internal Codex trust storage is inspected or changed.
