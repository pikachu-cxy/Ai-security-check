# Documentation

This directory contains current, maintainable project facts. Historical
acceptance output belongs in Git history, not in `docs/`.

## Start here

- [换电脑继续开发](DEVELOPMENT_HANDOFF.zh-CN.md) — branch sync, reproducible
  development environment/build/install, completed source fixes and tomorrow's gates.

- [最新首版开发接续计划](NEXT_DEVELOPMENT_PLAN.zh-CN.md) — consolidated decisions
  from the two current product conversations, completed work, next batches and pilot gates.
- [Runtime 收尾检查交付状态](RUNTIME_CLOSEOUT_CHECK.zh-CN.md) — current implementation,
  version-bound credential closure and independently recorded acceptance levels.
- [开发进度与验收状态](DEVELOPMENT_PROGRESS.md) — current implementation,
  source/isolated/package acceptance and pending Desktop checks.
- [安装与扫描能力准备验收](INSTALL_FLOW_ACCEPTANCE.zh-CN.md) — separate installation,
  live transfer feedback, bounded preparation, retained cache and local acceptance steps.
- [个人免费版与企业版规划](PRODUCT_ROADMAP.md) — P0/P1 scope, dependency evidence,
  update lifecycle and organization-management boundary; planned work is not
  implemented capability.
- [第一版受邀试用开发清单](PILOT_V1_CHECKLIST.zh-CN.md) — concrete P0 tasks,
  source and acceptance gaps, completion criteria, and work deferred until after
  a small Windows/Codex/Git pilot.
- [核心链路本地手动测试](MANUAL_CORE_TEST.zh-CN.md) — isolated Java/Python/JS/TS
  demos, real Hook and Stop observations, and manual multi-file context review.
- [开发任务结束安全核查方案](TASK_SECURITY_REVIEW_DESIGN.zh-CN.md) — task boundaries,
  static results plus bounded context, quick review workflow and quiet feedback.
- [任务核查与静默结束验收](TASK_SECURITY_REVIEW_ACCEPTANCE.zh-CN.md) — current implementation,
  native MCP/Hook measurements and pending real Desktop/Agent checks.
- [自动任务文件范围修复与验收](TASK_INVENTORY_ACCEPTANCE.zh-CN.md) — Git ignore-aware inventory,
  new-file coverage, bounded context and native automatic-scope verification.
- [订单详情上下文手测](BLIND_ORDER_CONTEXT_TEST.zh-CN.md) — anonymous paired projects and ordinary development prompts.

- [R2.2 security review contract](SECURITY_REVIEW.md)
- [Windows experience](WINDOWS_EXPERIENCE.md) / [中文体验](WINDOWS_EXPERIENCE.zh-CN.md)

- [Project context](PROJECT_CONTEXT.md) — the source of truth for resuming an
  AI-agent or developer session.
- [Architecture](ARCHITECTURE.md)
- [Decisions](DECISIONS.md)

## Architecture

- [Architecture](ARCHITECTURE.md)
- [Decisions](DECISIONS.md)
- [Functional verification boundary](FUNCTIONAL_VERIFICATION.md)

## Host integration

- [Codex integration](CODEX_INTEGRATION.md)
- Cursor's current verified state is recorded in
  [Project context](PROJECT_CONTEXT.md) and [Architecture](ARCHITECTURE.md).

## Detection / Rule Program

- [Rule foundation](RULE_FOUNDATION.md) — Java and JavaScript/TypeScript API scope,
  Hook measurement and the six-step local experience checklist.
- [Rule source inventory](RULE_SOURCE_INVENTORY.md) — upstream license decisions
  and the independent first-party implementation boundary.
- [Rule Program v1](RULE_PROGRAM.md)
- [Rule coverage matrix](RULE_COVERAGE_MATRIX.md)
- [Finding quality baseline](FINDING_QUALITY.md) — R2.1 independent review
  contract, stable correlation, local corpus workflow and metrics.
- [Scan target selection](SCAN_TARGET_SELECTION.md) — binary-document exclusions,
  bounded discovery diagnostics and coverage boundaries.

## Remediation

- [Smart auto-remediation](SMART_AUTO_REMEDIATION.md)

## Verification

- [Functional verification](FUNCTIONAL_VERIFICATION.md)

## Extension / Development

- [Extending the Runtime](EXTENDING.md)
- [升级与扫描入口优化清单](UPGRADE_AND_SCAN_USABILITY.zh-CN.md) — pending work,
  code-grounded gaps, acceptance gates and the next Codex development request.

## Documentation lifecycle

- Long-term facts → `docs/`
- Test fixtures and ground truth → `tests/fixtures/` or the owning test
  package
- Temporary acceptance output → `artifacts/` or an ignored temporary directory
- Release artifacts → `dist/`
- Historical versions → Git history

Do not add generated snapshots such as `docs/foo-before.json`,
`docs/foo-after.json`, or `docs/foo-final-final.json` to the repository.
