# 功能验证状态与企业版研发

Functional verification is an explicit Deep Verification flow. It is not part
of the default Core Hook because builds and tests are project-specific,
potentially expensive, and may have side effects.

Core security conclusions therefore come from the real scanner, normalized
Finding/Family/Episode state, policy, and bounded remediation proof. A missing
functional-verification capability keeps the result unknown or inconclusive;
it never becomes a safe result.

The personal edition currently hides this capability. The existing implementation
and explicit internal embedding opt-in remain available for compatibility and
development. Internal opt-in does not grant execution authority: a separate
explicit request and the required host capability are still necessary. Keep
build/test commands, environment prerequisites, and outputs outside `docs/`
unless they are a maintained contract.

## 个人版当前状态：暂时隐藏

个人版不再在修复后主动展示功能验证提示、推荐或选择，也不在默认 MCP 工具发现和
能力说明中提供功能验证入口。原问题的安全复查、修复状态和正常开发总结继续工作；
不会因为隐藏功能验证而阻塞安全修复或要求补做测试。

隐藏只改变产品露出，不表示功能已经验证。安全复查只证明其原规则、文件和实际覆盖内的
结果，不能由此宣称业务兼容、生产正确或 SAFE_TO_SHIP。未执行、证据不足与未知状态
仍保持原语义，不因不显示入口而变成通过。

## 保留的内部执行边界

底层实现和显式内部嵌入 opt-in 保留，不作为个人版默认入口或企业版已完成能力。
仅启用内部入口不会自动检测工具、复制项目、安排验证或启动构建和测试。取得单独的
明确请求和所需能力后，仍使用现有 prepare → 宿主执行原计划 → run → 合并结果流程。
功能检查不重新授权修复，也不恢复过期或丢失的修复权限；代码、计划与安全证明匹配时
复用现有验证缓存，不再启动相同测试。

内部显式执行时，原安全复查与功能结果分别记录和说明：

| 功能结果 | 用户呈现 |
| --- | --- |
| 测试通过 | 所执行本地检查通过，明确覆盖范围 |
| 仅编译或类型检查通过 | 业务功能测试尚未验证 |
| 失败 | 说明失败；没有修复前基线，不能归因为本次修复 |
| 部分、未执行或无法确认 | 明确保留未验证范围，不能显示为通过 |

当前可执行交接仍受原验证入口的修复上下文、确认时效与当前连接限制。没有原始验证
上下文时不伪造 continuation，不重建修复授权或直接执行测试。宿主不能从提示或内部
opt-in 生成执行权限。上下文分析风险的通用验证接入和修复前基线属于后续阶段。

## 企业版开发项：深度修复回归验证

状态：规划，尚未实现。企业版目标是在明确的业务契约内，结合真实执行证据判断安全修复是否
阻止目标漏洞场景，并保留约定的正常行为。现有 v0.1 宿主回执、编译检查与算术专项样例不等于此能力。

### 建议架构

本地 Runtime 提交修复任务与安全复查依据 → 企业控制服务固定前后版本、用例、环境和预算 →
企业内网隔离 Runner 创建两套独立环境 → 外部测试执行与状态检查 → 独立证据校验 → 分项报告。

| 层次 | 最小实现与边界 |
| --- | --- |
| 真实基线 | 保存实际修复前与修复后源码快照及补丁摘要；存在未提交代码时不以 Git HEAD 替代 |
| 固定验证契约 | 执行前确定正常业务断言、安全反例、允许变化、测试集摘要和来源；执行后不能为求通过而放宽 |
| 可比较环境 | 固定运行时、镜像 digest、依赖锁和初始化数据；前后使用各自全新的数据库和服务 |
| 外部验证器 | 在被测应用外检查 HTTP 响应、数据归属、状态变化和无副作用；应用不能自行宣称测试通过 |
| 隔离执行 | 客户专用 Linux 执行机起步，容器／沙箱限制挂载、网络、资源和时长；不向项目代码暴露 Docker socket |
| 证据与判定 | 保存测试身份、执行／跳过／失败数量、断言、前后版本和环境摘要；退出码 0 或有测试数量均不足以证明业务覆盖 |

测试工具候选：用 [Testcontainers](https://java.testcontainers.org/)准备临时依赖，
以 pytest 与 [Schemathesis](https://schemathesis.readthedocs.io/en/stable/)进行 API 契约和边界测试，
用 [Playwright](https://playwright.dev/docs/api-testing)处理明确的业务流程及后续浏览器场景。
执行隔离可评估 [gVisor](https://gvisor.dev/docs/architecture_guide/intro/)，兼容性与安全边界须按实际技术栈验收。

### 判定规则

- 正常业务：修复前后均满足批准的业务断言；前后结果不是对所有输入一概要求相等。
- 安全反例：先在隔离环境确认目标场景，修复后按约定拒绝，且不存在异常数据副作用。
- 既有失败、新增失败、环境失败、未执行和证据不足分别记录，不统一归因为本次修复。
- 已有测试、企业批准测试、模型生成测试分别标明来源；关键用例通过已知失败版本或受控故障变体核对有效性。
- AI 辅助设计用例与解释失败；固定断言与实际执行决定结果。AI 不同时修改代码、测试和通过标准。
- 新增企业证据协议，不把现有不可信宿主回执直接升级为可信 Runner 证明；证据签名也不证明测试设计正确。

### 分阶段实施

1. E1：单服务、单次修复和单数据库，固定真实前后快照、契约、数据与报告格式。
2. E2：以 Spring Boot/Maven HTTP API 与 PostgreSQL 为候选，接通登录、权限和基本 CRUD 的独立环境回归。
3. E3：加入契约／边界输入、测试有效性检查、失败复现与受限 AI 辅助。
4. E4：按企业试点扩大多服务、多环境、浏览器流程、权限审批和任务调度。

这些阶段不作为个人版首发门槛。下一阶段个人版开发优先扩大宿主接入，见[近期计划](NEXT_DEVELOPMENT_PLAN.zh-CN.md)
与[宿主支持](HOST_SUPPORT.md)。

## 本地计时与验收

`scripts/benchmarks/functional_verification_benchmark.py` 分别计时安全复查摘要生成与真实 Python 测试进程。
该脚本保留为内部计时工具，不表示个人版会显示提示或安排检查。它使用合成项目且不运行
安全扫描、不提交模拟执行回执。将源码目录放到 PYTHONPATH，使用已具备 pytest 的本地
Python；`--output` 指向忽略的 artifacts 目录。
结果区分呈现路径开销、显式执行后的测试开销和实际测试范围；不能推算为真实桌面模型
回复耗时。真实开发对照应保持项目初始代码、模型、设置一致，各开新聊天，分别记录
个人版默认流程与内部 opt-in 执行的耗时，不能把内部测试开销加入默认流程的阻塞等待。
