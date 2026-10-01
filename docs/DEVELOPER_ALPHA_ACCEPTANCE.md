# Developer Alpha Acceptance Hardening — 2026-10-01

本报告使用隔离 Git 项目、实际本机引擎和官方 MCP SDK。项目包含 16 层源文件及被 Git 忽略的 16 层缓存目录（300 个文件）。原始输出见 [JSON 证据](alpha_acceptance-evidence.json)，复现命令为 `python scripts/alpha_acceptance.py --output <json>`。没有把测试 SDK 调用描述成真实 WorkBuddy UI 调用。

## A / B — HEAD 与分支

A：`273855f2f4d3978990267775ea83fab904ba0a24`。开始时 `feature/runtime-mvp`，工作区干净。
B：本报告所在交付提交的 SHA 见最终交付消息或 `git log -1 --format=%H`。只提交和推送 `feature/runtime-mvp`，没有修改或合并 main。

## C — 修改文件

- `README.md`
- `README.zh-CN.md`
- `docs/DEVELOPER_ALPHA_ACCEPTANCE.md`
- `docs/alpha_acceptance-evidence.json`
- `scripts/alpha_acceptance.py`
- `scripts/verify_artifact.py`
- `src/security_runtime/capabilities.py`
- `src/security_runtime/cli.py`
- `src/security_runtime/integration_config.py`
- `src/security_runtime/integration_state.py`
- `src/security_runtime/integrations.py`
- `src/security_runtime/mcp_server.py`
- `src/security_runtime/mcp_verify.py`
- `src/security_runtime/models.py`
- `src/security_runtime/runtime.py`
- `src/security_runtime/scanners.py`
- `src/security_runtime/target.py`
- `tests/test_alpha_acceptance.py`
- `tests/test_doctor.py`
- `tests/test_e2e_real.py`
- `tests/test_git.py`


## D — P0 / P1 / P2 处理方式

| 优先级 / 问题 | 最终处理 |
| --- | --- |
| P0 结果语义 | NO_CHANGES/NONE/NOT_ASSESSED；无扫描不输出 SAFE/FULL 或提交安全结论；JSON/MCP 明确 execution_state、coverage_scope、capability_results。 |
| P0 CLI summary | render 优先保留 Runtime 的 summary，包括执行过的结果；正式回归覆盖。 |
| P0 Runtime MCP 配置污染 | 新建 Runtime 项目配置写可逆的 .git/info/exclude 独立块；保留原始字节和既有规则；不改共享 .gitignore；不隐藏原有混合配置或认领 tracked 配置；ignore 写入失败会回滚配置。 |
| P0/P1 大型 Git 项目 | quick/feature 使用变更文件与必要 manifest；feature 包含父目录 manifest；release 使用 Git 有效文件列表。显式列表不套 recursive depth limit；保留数量、大小、越界、symlink/junction 保护。 |
| P0 实际 Scanner 边界 | Semgrep 使用显式文件批次；release Gitleaks、feature/release Trivy 使用仅包含 scoped files/context 的临时镜像，不递归无关缓存仓库。 |
| P0 verify | 只 profile 受影响文件，只调用原始 Scanner；任何原始检查失败/缺失均不能判 RESOLVED；深层缓存不影响验证。 |
| P1 doctor | Git 列表 profiling；DiscoveryLimitError 降级为 Profile LIMITED 和 warning，工具、Git、workspace、integrations 仍可诊断，exit 0。 |
| P0 WorkBuddy native 状态 | 配置、Runtime 自测、最后真实调用分别展示；自测进程有独立标识，不写 CONNECTED；正常 MCP tool invocation 才更新连接时间；修复 Windows 短路径/规范路径误判。 |
| P1 NOT_APPLICABLE | 与 FAILED/UNAVAILABLE/TIMEOUT 分离；human output 分 Executed/Not applicable，不把不适用当失败。 |
| P1 engine preparation | 删除 CLI 全工具预下载；Scope → Profile → Plan → adapter ensure；无变更不准备工具，Secret-only 不准备 Trivy DB。 |
| P2 CLI onboarding | 主要命令加入一句描述，保留 --version；无项目错误显示当前命令的 --path 用法。 |
| 保持既有边界 | 未改 ToolManager 优先级、offline、licensing、fingerprint 算法、Scanner plugin API、五个 MCP 工具或 LLM 依赖。补 staged/unstaged fingerprint 回归。 |

FULL 只描述适用计划在选中文件上的执行，不表示全仓或所有安全能力。代码检查不适用但其它适用检查成功时显示 SCOPED。

## E — CLI no-change 真实输出


```text
AI Security Check

没有需要检查的代码变更。
本次没有执行代码安全扫描。
Status: NO_CHANGES
耗时：287 ms

```

exit code: 0

## F — MCP no-change 真实 JSON


```json
{
  "scan_id": "0acafaa5-5e67-4cea-9d91-e3be39a7bdd6",
  "workspace": "C:\\Users\\Administrator\\AppData\\Local\\Temp\\alpha-acceptance-68it_vev\\project",
  "status": "NO_CHANGES",
  "execution_state": "NO_CHANGES",
  "coverage_scope": "PLANNED_FILES",
  "capability_results": {
    "CODE_SAST": "NOT_APPLICABLE",
    "SECRET_SCAN": "NOT_APPLICABLE",
    "DEPENDENCY_VULN": "NOT_APPLICABLE",
    "IAC_MISCONFIG": "NOT_APPLICABLE"
  },
  "coverage": "NONE",
  "summary": "没有需要检查的代码变更。\n本次没有执行代码安全扫描。",
  "findings": [],
  "recommendation": "NOT_ASSESSED",
  "duration_ms": 268,
  "scanner_runs": [
    {
      "scanner": "semgrep",
      "status": "NOT_APPLICABLE"
    },
    {
      "scanner": "gitleaks",
      "status": "NOT_APPLICABLE"
    },
    {
      "scanner": "trivy",
      "status": "NOT_APPLICABLE"
    }
  ]
}
```


## G — doctor 大型/深目录项目真实输出


```text
AI Security Runtime

Workspace
C:\Users\Administrator\AppData\Local\Temp\alpha-acceptance-68it_vev\project
Workspace: READY
Git: READY
Languages: Python
Profile: READY

Security capabilities
Code Security          ✓
Secret Security        ✓
Dependency Security    ✓
IaC Security           ✓

Integrations
Cursor         DETECTED
  scope: PROJECT
  config_path: C:\Users\Administrator\AppData\Local\Temp\alpha-acceptance-68it_vev\project\.cursor\mcp.json
  workspace: C:\Users\Administrator\AppData\Local\Temp\alpha-acceptance-68it_vev\project
  last_verified: -
  mcp_health: -
  command_path: -
  configuration_status: MISSING
  runtime_self_test: UNKNOWN
  last_client_invocation: -
Workbuddy      NEEDS_RESTART
  scope: PROJECT
  config_path: C:\Users\Administrator\AppData\Local\Temp\alpha-acceptance-68it_vev\project\.workbuddy\mcp.json
  workspace: C:\Users\Administrator\AppData\Local\Temp\alpha-acceptance-68it_vev\project
  last_verified: 2026-10-01T03:41:27.747034+00:00
  mcp_health: RUNTIME_VERIFIED
  command_path: C:\Users\Administrator\AppData\Local\Programs\Python\Python313\Scripts\security-check.exe
  configuration_status: WRITTEN
  runtime_self_test: PASSED
  last_client_invocation: -
Generic-Mcp    AVAILABLE
  scope: PROJECT

Runtime
Git: READY

Semgrep
Status: READY
Version: 1.178.0
Source: SYSTEM
Path: C:\Users\Administrator\AppData\Local\Programs\Python\Python313\Scripts\semgrep.exe

Gitleaks
Status: READY
Version: 8.30.0
Source: MANAGED
Path: C:\Users\Administrator\AppData\Local\AI-Security-Runtime\tools\gitleaks\8.30.0\gitleaks.exe

Trivy
Status: READY
Version: 0.74.0
Source: MANAGED
Path: C:\Users\Administrator\AppData\Local\AI-Security-Runtime\tools\trivy\0.74.0\trivy.exe
Database: READY
Updated: 2026-10-01T01:24:14.992991033Z

Runtime ready.

```


将 MAX_FILES 降至 1 强制 profile limit；诊断仍 exit 0：


```text
AI Security Runtime

Workspace
C:\Users\Administrator\AppData\Local\Temp\alpha-acceptance-68it_vev\project
Workspace: READY
Git: READY
Languages: Unknown
Profile: LIMITED
Warning: Project profiling was limited because automatic discovery exceeded configured limits. Scanning can still use Git-scoped files.

Security capabilities
Code Security          ✓
Secret Security        ✓
Dependency Security    ✓
IaC Security           ✓

Integrations
Cursor         DETECTED
  scope: PROJECT
  config_path: C:\Users\Administrator\AppData\Local\Temp\alpha-acceptance-68it_vev\project\.cursor\mcp.json
  workspace: C:\Users\Administrator\AppData\Local\Temp\alpha-acceptance-68it_vev\project
  last_verified: -
  mcp_health: -
  command_path: -
  configuration_status: MISSING
  runtime_self_test: UNKNOWN
  last_client_invocation: -
Workbuddy      NEEDS_RESTART
  scope: PROJECT
  config_path: C:\Users\Administrator\AppData\Local\Temp\alpha-acceptance-68it_vev\project\.workbuddy\mcp.json
  workspace: C:\Users\Administrator\AppData\Local\Temp\alpha-acceptance-68it_vev\project
  last_verified: 2026-10-01T03:41:27.747034+00:00
  mcp_health: RUNTIME_VERIFIED
  command_path: C:\Users\Administrator\AppData\Local\Programs\Python\Python313\Scripts\security-check.exe
  configuration_status: WRITTEN
  runtime_self_test: PASSED
  last_client_invocation: -
Generic-Mcp    AVAILABLE
  scope: PROJECT

Runtime
Git: READY

Semgrep
Status: READY
Version: 1.178.0
Source: SYSTEM
Path: C:\Users\Administrator\AppData\Local\Programs\Python\Python313\Scripts\semgrep.exe

Gitleaks
Status: READY
Version: 8.30.0
Source: MANAGED
Path: C:\Users\Administrator\AppData\Local\AI-Security-Runtime\tools\gitleaks\8.30.0\gitleaks.exe

Trivy
Status: READY
Version: 0.74.0
Source: MANAGED
Path: C:\Users\Administrator\AppData\Local\AI-Security-Runtime\tools\trivy\0.74.0\trivy.exe
Database: READY
Updated: 2026-10-01T01:24:14.992991033Z

Runtime ready.

```


## H — feature large repo


```json
{
  "status": "COMPLETED",
  "execution_state": "EXECUTED",
  "coverage": "FULL",
  "coverage_scope": "PLANNED_FILES",
  "capability_results": {
    "CODE_SAST": "EXECUTED",
    "SECRET_SCAN": "EXECUTED",
    "DEPENDENCY_VULN": "EXECUTED",
    "IAC_MISCONFIG": "NOT_APPLICABLE"
  },
  "scanner_runs": [
    {
      "scanner": "semgrep",
      "version": "1.178.0",
      "status": "SUCCESS",
      "duration_ms": 3982,
      "finding_count": 1,
      "error": ""
    },
    {
      "scanner": "gitleaks",
      "version": "8.30.0",
      "status": "SUCCESS",
      "duration_ms": 1129,
      "finding_count": 1,
      "error": ""
    },
    {
      "scanner": "trivy",
      "version": "0.74.0",
      "status": "SUCCESS",
      "duration_ms": 990,
      "finding_count": 4,
      "error": ""
    }
  ],
  "duration_ms": 4903,
  "findings_count": 5,
  "recommendation": "BLOCKED"
}
```


## I — release large repo


```json
{
  "status": "COMPLETED",
  "execution_state": "EXECUTED",
  "coverage": "FULL",
  "coverage_scope": "PLANNED_FILES",
  "capability_results": {
    "CODE_SAST": "EXECUTED",
    "SECRET_SCAN": "EXECUTED",
    "DEPENDENCY_VULN": "EXECUTED",
    "IAC_MISCONFIG": "NOT_APPLICABLE"
  },
  "scanner_runs": [
    {
      "scanner": "semgrep",
      "version": "1.178.0",
      "status": "SUCCESS",
      "duration_ms": 7162,
      "finding_count": 1,
      "error": ""
    },
    {
      "scanner": "gitleaks",
      "version": "8.30.0",
      "status": "SUCCESS",
      "duration_ms": 650,
      "finding_count": 1,
      "error": ""
    },
    {
      "scanner": "trivy",
      "version": "0.74.0",
      "status": "SUCCESS",
      "duration_ms": 934,
      "finding_count": 4,
      "error": ""
    }
  ],
  "duration_ms": 7336,
  "findings_count": 5,
  "recommendation": "BLOCKED"
}
```


## I — MCP scan_project large repo


```json
{
  "status": "COMPLETED",
  "execution_state": "EXECUTED",
  "coverage": "FULL",
  "coverage_scope": "PLANNED_FILES",
  "capability_results": {
    "CODE_SAST": "EXECUTED",
    "SECRET_SCAN": "EXECUTED",
    "DEPENDENCY_VULN": "EXECUTED",
    "IAC_MISCONFIG": "NOT_APPLICABLE"
  },
  "scanner_runs": [
    {
      "scanner": "semgrep",
      "status": "SUCCESS"
    },
    {
      "scanner": "gitleaks",
      "status": "SUCCESS"
    },
    {
      "scanner": "trivy",
      "status": "SUCCESS"
    }
  ],
  "duration_ms": 6824,
  "findings_count": 5,
  "recommendation": "BLOCKED"
}
```


## J — verify large repo
修复前：


```json
[
  {
    "finding_id": "7d8b48f20cfffa397c56811d",
    "status": "STILL_PRESENT"
  },
  {
    "finding_id": "947d27fe485d50fe801a8001",
    "status": "STILL_PRESENT"
  }
]
```

修复后：


```json
[
  {
    "finding_id": "7d8b48f20cfffa397c56811d",
    "status": "RESOLVED"
  },
  {
    "finding_id": "947d27fe485d50fe801a8001",
    "status": "RESOLVED"
  }
]
```


## K — WorkBuddy 状态真实输出


```text
AI Security Runtime

AI Coding integrations
Cursor       DETECTED
  config_path: C:\Users\Administrator\AppData\Local\Temp\alpha-acceptance-68it_vev\project\.cursor\mcp.json
  configuration_status: MISSING
  runtime_self_test: UNKNOWN
  last_client_invocation: -
WorkBuddy    NEEDS_RESTART
  config_path: C:\Users\Administrator\AppData\Local\Temp\alpha-acceptance-68it_vev\project\.workbuddy\mcp.json
  configuration_status: WRITTEN
  runtime_self_test: PASSED
  last_client_invocation: -

Other tools
Generic MCP  AVAILABLE
CLI          AVAILABLE

```

安装结果：


```json
{
  "status": "NEEDS_RESTART",
  "details": {
    "scope": "PROJECT",
    "config_path": "C:\\Users\\Administrator\\AppData\\Local\\Temp\\alpha-acceptance-68it_vev\\project\\.workbuddy\\mcp.json",
    "workspace": "C:\\Users\\Administrator\\AppData\\Local\\Temp\\alpha-acceptance-68it_vev\\project",
    "last_verified": "2026-10-01T03:41:27.747034+00:00",
    "mcp_health": "RUNTIME_VERIFIED",
    "command_path": "C:\\Users\\Administrator\\AppData\\Local\\Programs\\Python\\Python313\\Scripts\\security-check.exe",
    "configuration_status": "WRITTEN",
    "runtime_self_test": "PASSED",
    "last_client_invocation": ""
  }
}
```


原生配置仍为明确项目绑定。官方文档列出项目 `.workbuddy/mcp.json`；5.6.2 实测 UI 全局 `.workbuddy-ai/mcp.json` 的差异已记录在双语 README。自动全局注册没有实现，避免把某项目永久绑定为全局 workspace。真实 WorkBuddy UI 本轮未重新执行，不能宣称已连接。正式测试用 SDK 验证真实调用更新记录、自测不更新记录。


## L — 实际 Scanner 与 stable fingerprint


```json
{
  "semgrep": {
    "status": "READY",
    "version": "1.178.0"
  },
  "gitleaks": {
    "status": "READY",
    "version": "8.30.0"
  },
  "trivy": {
    "status": "READY",
    "version": "0.74.0"
  }
}
```

quick 实际运行：


```json
[
  {
    "scanner": "semgrep",
    "version": "1.178.0",
    "status": "SUCCESS",
    "duration_ms": 5884,
    "finding_count": 1,
    "error": ""
  },
  {
    "scanner": "gitleaks",
    "version": "8.30.0",
    "status": "SUCCESS",
    "duration_ms": 1015,
    "finding_count": 1,
    "error": ""
  },
  {
    "scanner": "trivy",
    "version": "",
    "status": "NOT_APPLICABLE",
    "duration_ms": 0,
    "finding_count": 0,
    "error": ""
  }
]
```

Semgrep 和 Gitleaks 各发现一个 HIGH Finding；feature/release Trivy SUCCESS，归一化后合计 5 个 Finding。所有测试 credential 均为固定合成 fixture，输出 evidence 已脱敏。


```json
{
  "staged": [
    "7d8b48f20cfffa397c56811d",
    "947d27fe485d50fe801a8001"
  ],
  "unstaged": [
    "7d8b48f20cfffa397c56811d",
    "947d27fe485d50fe801a8001"
  ]
}
```


## M — 完整 pytest

基线：`63 passed, 3 failed, 6 skipped, 5 subtests passed in 19.62s`。
失败是两项 UTF-8 subprocess 被 GBK 解码的测试问题，以及本机缺少声明的 Semgrep 测试依赖。
普通 sandbox 测试还遇到 Windows 临时目录权限失败；正常权限下取得上述产品基线。

最终：`86 passed, 6 skipped, 5 subtests passed in 76.41s`。
6 项既有 real-E2E 测试因 managed binaries 没有加入全局 PATH 而跳过；实际 Scanner loop、MCP 与深目录验收由本报告独立的真实引擎脚本完成。没有把 skipped 当成通过。

## N — Compliance

`security-check licenses --check-distribution`：exit 0；Semgrep LGPL-2.1-only REVIEWED，Gitleaks MIT OK，Trivy Apache-2.0 OK。
`python scripts/generate_notices.py --check`：exit 0，THIRD_PARTY_NOTICES.md matches reviewed metadata。
Compliance + Distribution 单独回归：`10 passed, 5 subtests passed in 3.25s`。

## O — Package integrity

`python -m build`：成功生成 sdist 和 wheel（0.3.1）。
`python scripts/check_wheel.py`：Wheel compliance OK，1 first-party rule file。
`python scripts/verify_package.py`：干净 venv 安装、CLI help/version、licenses、规则与分发文件验证通过，Installed wheel integrity OK。

## P — GitHub Actions

提交推送后的实时状态和链接见最终交付消息。不要把本机通过描述成四平台 native CI 已通过；本轮没有修改 release workflows，standalone verifier 的 NOT_APPLICABLE 断言已同步更新。

## Q — 剩余限制

- 未重新操作真实 WorkBuddy 5.6.2 UI；客户端版本路径差异仍需在该版本完成实际调用确认。Generic MCP SDK 与状态逻辑已验证。
- 未取得原始 ai-audit-backend 的本机路径；深目录验收使用可复现隔离项目，不冒充原始仓库 dogfood。
- Trivy 默认 mirror.gcr.io 在本机网络超时，切换官方 GHCR 来源后 DB READY，最终扫描使用已准备数据库的 offline 模式；未修改默认 toolchain 来源或绕过校验。
- 本机为 Windows Python 3.13；跨平台 standalone 的本轮最终状态以 Actions 为准。
- 尚未实现自动 WorkBuddy global registration；未开发新 Scanner、内置 LLM、AI provider、发布渠道或 GUI。
