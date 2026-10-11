# Architectural Decisions

Only current decisions are recorded here. Historical alternatives and
milestone logs remain available through Git history.

## ADR-001 — Scanner-backed security truth

- Decision: Runtime security truth is derived from scanner evidence, normalized
  findings, policy, and proof; it is not delegated to an Agent.
- Reason: A host or model may be unavailable, ambiguous, or untrusted.
- Status: Accepted.

## ADR-002 — Core is deterministic and bounded

- Decision: Core hooks reconcile workspace changes, scan, apply policy, and
  require proof. Core does not default to build/test or deep verification.
- Reason: The always-on path must remain predictable and local-first.
- Status: Accepted.

## ADR-003 — Capability-first Rule Program

- Decision: Product capabilities own underlying scanner variants and map to
  Finding Family/Episode semantics; YAML rule count is an implementation detail.
- Reason: Capability maturity and coverage must remain stable as variants evolve.
- Status: Accepted.

## ADR-004 — Explicit scanner ownership

- Decision: Semgrep covers code patterns, Gitleaks covers secrets, and Trivy/OSV
  cover dependency domains with explicit fallback boundaries.
- Reason: Engine-specific evidence and limitations must not be conflated.
- Status: Accepted.

## ADR-005 — Narrow remediation authorization

- Decision: Only narrow deterministic fixes may be AUTO_FIX eligible. Policy,
  bounded scope, exact edit envelopes, and a real scanner re-scan remain
  mandatory. `INLINE_PREPARED` is a prepared transport, not proof by itself.
- Reason: Fix convenience cannot weaken security authorization or evidence.
- Status: Accepted.

## ADR-006 — Host capability separation

- Decision: Hooks provide deterministic detection/enforcement; MCP can provide
  Agent chat UX when the host exposes that capability.
- Reason: Cursor `postToolUse` is not a reliable observed feedback channel, and
  configuration writeability is not Desktop verification.
- Status: Accepted.

## ADR-007 — Global Codex semantic ownership

- Decision: Global ownership binds only `mcp_servers.ai_security_runtime` and
  its descendants to a signed sidecar manifest, GLOBAL scope, server identity,
  semantic fingerprint and Runtime version/contract. Comments are not ownership
  boundaries in the shared user-level config. Project legacy remains delimited.
- Reason: Real Desktop restart trials lost marker comments while preserving the
  server definition. The specific writer was not established. No assumption of
  permanent comment preservation is part of the public configuration contract.
- Mutation: Parse the entire TOML first, prove signed ownership, locate complete
  structural statements, replace only the exact MCP subtree, reparse and compare
  all unrelated semantics. Preserve sibling bytes; refuse ambiguous inline-parent
  mutation. Retain HMAC, CAS, interrupted-write recovery and exact hook ownership.
- Status: Accepted; post-restart Desktop stability requires separate evidence.

## ADR-008 — Independent finding quality review

- Decision: Keep scanner truth, existing AI validation and quality review
  decisions separate. Add a portable quality ID without replacing legacy
  workspace-scoped DB, family, episode or remediation references.
- Review: Explicit six-state decisions with HUMAN/AI/POLICY attribution,
  reason and UTC timestamp; append-only history scoped to workspace, scan and
  observation digest. No automatic label inheritance, suppression or fixing.
- Evidence: Describe only stored scanner evidence; no invented source/sink or
  dataflow. Private real corpus outputs remain local and ignored; tests are
  synthetic. Unreviewed is not TP; recall requires independent ground truth.
- Status: Implemented for R2.1 baseline; user review precedes R2.2 AI triage.

## ADR-009 — Local evidence rehydration without scanner truth mutation

- Decision: Retain bounded locator/scan-time file hashes and rehydrate local
  code only for explicit detail requests. Preserve original scanner placeholders
  and real scanner metadata; do not patch engine login gating or invent traces.
- Boundary: Canonical workspace containment, no links/junctions/alternate streams,
  opened-file identity/revision checks, strict decode and file/context budgets.
- Freshness: EXACT requires a captured matching full-file hash. STALE and missing
  historical hashes cannot certify current_context as original scanner evidence.
- Privacy: Secret findings remain redacted without source reads. Other excerpts
  scrub credential patterns/known ranges/literals; private exports stay ignored.
  No source/local excerpts are added to persisted Finding snapshots.
- Compatibility: Finding IDs, review observation hashes, scanner outcomes,
  FULL/PARTIAL semantics and Global ownership remain unchanged. Line-movement
  correlation belongs to future Finding Episode work.
- Status: R2.1.1 implementation; no AI triage or automatic fix is introduced.

## ADR-010 — Change-triggered dependency checks in quick scans and Hooks

- Decision: Quick and feature planning requests dependency vulnerability checks
  when a validated changed path names a dependency manifest or lockfile, including
  deleted inputs. Discovery, planning and providers share dependency filename
  identity. Ordinary source-only edits do not trigger dependency checks solely
  because an unchanged manifest exists elsewhere in the project.
- Scope: Reevaluate the remaining dependency inputs associated with the affected
  scope. Quick dependency checks reuse local offline tools and data. Existing Hook
  workspace/path validation, bounded snapshots and offline execution remain
  mandatory. CLI quick/feature/staged retain their Git boundary.
  Never install target dependencies, run package managers or build the target.
- Evidence: Recognition of a manifest is not evidence of engine execution,
  inventory completeness or a complete transitive graph. Missing/failed engines,
  missing/stale vulnerability data and unsupported extraction remain explicit
  incomplete coverage. A removed input cannot certify an empty runtime inventory.
- Reason: A source-only fast path keeps routine edits predictable, while ignoring
  newly added vulnerable dependencies defeats the developer security workflow.
- Status: Accepted; provider inventory and actual execution determine coverage.

## ADR-011 — Product-owned engine and security-data preparation

- Decision: `install codex` is the public initial-install, upgrade and retry
  entry point. After owned configuration and Skill installation succeed, it
  verifies bundled rules, prepares the default engines and refreshes missing or
  expired vulnerability data once using the selected new Runtime. Portable
  delivery's child `setup codex` remains configuration-only so the parent owns
  preparation without duplicate downloads or a short setup timeout cutting off
  a long database download.
- Compatibility: Engine releases are pinned to versions tested with the Runtime
  and provider output contracts. Valid exact-compatible local caches may be
  reused. An unsupported explicit tool override remains an actionable mismatch;
  it is neither overwritten nor silently reported as ready. Rules travel with
  the product; vulnerability data has separate schema and freshness checks.
  Optional dependency fallback engines remain on demand.
- Readiness: Configuration success is separate from scanning readiness and
  observed Desktop connectivity. Failed preparation retains the configuration
  and previous usable cache, returns an explicit not-ready result and a nonzero
  CLI exit code, and directs the user to retry the product installation. It
  cannot turn stale/unknown data into fresh coverage or imply a clean project.
- Boundaries: Explicit offline installation only verifies existing assets.
  Automatic Hooks and quick dependency checks keep their local offline contract.
  Product preparation never installs the protected project's dependencies,
  invokes its package manager or executes its code. Plain `setup codex` remains
  a configuration operation and cannot attest scanning readiness.
- Industry evidence: Endor Labs documents cached `npx` delivery, optional CLI
  version pinning and cloud-backed MCP queries; it does not establish the private
  engines or data-update mechanics behind every product capability.
  [Endor Labs MCP](https://docs.endorlabs.com/setup-deployment/mcp/gemini).
  Its official AI governance deployment scripts install `endorctl` on first use,
  throttle update checks to 24 hours, verify SHA-256 and support skipping updates.
  POSIX downloads run in the background with resume and concurrency protection;
  Windows downloads remain in the foreground. This is evidence about that
  deployment solution, not every Endor product's private implementation.
  [Endor Labs governance deployment](https://github.com/endorlabs/mdm-scripts/blob/main/agent-governance/README.md).
  Endor's SBOM Hub documents continuous assessment against newly published
  advisories without rescanning. We infer from this that vulnerability-data
  freshness should be managed separately from client-release cadence.
  [Endor Labs SBOM Hub](https://www.endorlabs.com/use-case/sbom-hub-vex).
  Snyk's unified IDE configuration documents automatic CLI binary management,
  stable/RC/preview release channels and explicit version pinning. Its release
  policy recommends the stable channel.
  [Snyk unified IDE binary management](https://docs.snyk.io/developer-tools/integrations/snyk-ide-plugins-and-extensions/unified-ide-configuration-dialog),
  [Snyk CLI channels](https://docs.snyk.io/developer-tools/snyk-cli/releases-and-channels-for-the-snyk-cli).
  Trivy separates engine delivery from automatically maintained database assets,
  supports database-only preparation and skip-update execution, and defaults DB
  tags to schema versions.
  [Trivy databases](https://trivy.dev/docs/latest/configuration/db/).
- Follow-up: Vulnerability data can expire between product releases. A bounded,
  product-owned background data refresh is a future extension; this decision
  does not introduce a scheduler or permit network work in automatic Hooks.
- Reason: Users should install or update one product and receive a truthful
  protection-readiness result, rather than maintain hidden engine components.
- Status: Accepted.
