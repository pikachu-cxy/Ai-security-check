# Stop 最小修复验证记录

本轮只修改工作区源码，未安装、打包替换或切换本机当前版本。当前安装仍为 0.3.11，构建 6abfaef0e47e。

## 实现范围

- 编辑事件沿现有检查保存本回合标记和起始变更序号，Codex 传递 turn_id，Cursor 传递 generation_id。Stop 只处理本轮编辑或其已经开始的续接；旧记录和其他只读回合不补扫。无实际新增记录的可能写入操作不重启旧检查。
- 证据缺失、未知、过期或未覆盖风险行时，原复核接口返回明确错误和 read_development_risk_context 的文件、行及原会话参数。失败提交不保存复核，不扫描，不放松归属、版本或证据校验。
- 共享回复指导及随包方法要求：使用真实 evidence_ref 补读重试，仍失败就报告障碍并结束；后续 Stop 不重启同一失败循环。成功提交仍从 offset=0 重读风险及处置。
- 保留已有 Stop 次数和时间预算，不新增数据库、失败状态机或重试计数器。指导不能保证模型只触发一次 Stop；最终防无限续接仍由既有预算负责。

## 测试

- 主回归：201 项通过，包括统一配置、检查存储、实际 MCP 路由、证据恢复、提交后重读、Codex/Cursor 适配与指导一致性。
- 另组宿主规范化、Cursor 自动接入及轻量 Hook：111 项通过。
- 原生文件监听与 Pre/Post Hook：最终普通本机权限整组 16 项通过。
- 后补的 Codex/Cursor 原生回合隔离：2 项通过。合计覆盖 330 个不同用例。
- git diff --check 通过。

测试过程中，受限执行环境有 7 项未收到原生文件通知；普通权限复跑均恢复。另有一次只读监听测试捕获了 read.py，导致断言失败。已安装版本和工作区版本单独各复跑两次均通过，工作区监听整组最终也通过；该偶发时序原因尚未完全定位。本轮没有修改监听实现、增加延迟或放宽断言来消除失败。自动化测试不代替 Codex 桌面实际验收。

## 开发静态检查

已沿原检查完成本次已观测文件的静态扫描并读完全部风险分页；扫描覆盖为 PARTIAL，仍有 SCANNER_COVERAGE_LIMITED。两项 Agent 分析按用户现有配置均关闭，因此以下是未复核扫描候选，不能视作 Agent 确认的漏洞。历史已排除记录不重复提醒。本轮当前需呈现候选 15 条，按同类规则合并列示，未据此修改源码。

### 工具入口被判定为未使用：13 条候选

级别：HIGH，为 OpenGrep 原始映射评级；类别为维护性，尚无 Agent 安全评级。位置及函数：

- [record_development_changes](/Users/cxy/Documents/Codex/2026-10-18/kaq/Ai-security-check/latest-source-20261031/src/security_runtime/mcp_tools/development_check.py:114)
- [begin_development_check](/Users/cxy/Documents/Codex/2026-10-18/kaq/Ai-security-check/latest-source-20261031/src/security_runtime/mcp_tools/development_check.py:105)
- [get_development_risks](/Users/cxy/Documents/Codex/2026-10-18/kaq/Ai-security-check/latest-source-20261031/src/security_runtime/mcp_tools/development_check.py:61)
- [declare_development_outputs](/Users/cxy/Documents/Codex/2026-10-18/kaq/Ai-security-check/latest-source-20261031/src/security_runtime/mcp_tools/development_check.py:123)
- [get_development_result](/Users/cxy/Documents/Codex/2026-10-18/kaq/Ai-security-check/latest-source-20261031/src/security_runtime/mcp_tools/development_check.py:169)
- [prepare_development_risk_fix](/Users/cxy/Documents/Codex/2026-10-18/kaq/Ai-security-check/latest-source-20261031/src/security_runtime/mcp_tools/development_check.py:74)
- [finish_development_check](/Users/cxy/Documents/Codex/2026-10-18/kaq/Ai-security-check/latest-source-20261031/src/security_runtime/mcp_tools/development_check.py:130)
- [get_development_deliveries](/Users/cxy/Documents/Codex/2026-10-18/kaq/Ai-security-check/latest-source-20261031/src/security_runtime/mcp_tools/development_check.py:162)
- [set_development_risk_disposition](/Users/cxy/Documents/Codex/2026-10-18/kaq/Ai-security-check/latest-source-20261031/src/security_runtime/mcp_tools/development_check.py:67)
- [wait_development_check](/Users/cxy/Documents/Codex/2026-10-18/kaq/Ai-security-check/latest-source-20261031/src/security_runtime/mcp_tools/development_check.py:155)
- [get_development_check](/Users/cxy/Documents/Codex/2026-10-18/kaq/Ai-security-check/latest-source-20261031/src/security_runtime/mcp_tools/development_check.py:141)
- [complete_development_check](/Users/cxy/Documents/Codex/2026-10-18/kaq/Ai-security-check/latest-source-20261031/src/security_runtime/mcp_tools/development_check.py:148)
- [submit_development_risk_resolution](/Users/cxy/Documents/Codex/2026-10-18/kaq/Ai-security-check/latest-source-20261031/src/security_runtime/mcp_tools/development_check.py:85)

**问题**：扫描器认为这些嵌套函数没有使用；返回片段同时包含 @server.tool 装饰器。扫描记录未说明是否识别了装饰器注册和宿主调用。

**可能影响**：只有入口确实没有正确注册或不可调用时，相关开发检查功能才可能不可用；这条规则命中本身不能证明该影响已经存在。

**建议修复**：先核对注册和实际调用证据，再决定排除候选或修复入口；不要仅据此删除函数。

**尚未确认**：本批次未启用 Agent 复核，未确认这些候选是否成立。

### SQL 拼接候选：1 条

级别：HIGH，来源 OpenGrep 原始评级，扫描置信度 LOW，未获 Agent 确认。
位置：[development_check.py:128](/Users/cxy/Documents/Codex/2026-10-18/kaq/Ai-security-check/latest-source-20261031/src/security_runtime/development_check.py:128)。扫描记录未提供所属函数名；片段调用 self._select()。

**问题**：规则匹配到 SELECT 片段和 SQL 后缀拼接；返回片段中的 cursor 使用参数绑定。

**可能影响**：若拼接的 SQL 结构包含外部可控内容，才可能改变查询语义；现有命中没有证明该条件。

**建议修复**：先核对 SQL 结构的来源及参数化边界，再决定是否需要修复，保留现有值参数绑定。

**尚未确认**：未执行 Agent 数据流复核，尚未证明存在可利用的注入路径。

### 函数外 return 候选：1 条

级别：MEDIUM，来源 OpenGrep 原始评级，未获 Agent 确认。
位置：[host_events.py:74](/Users/cxy/Documents/Codex/2026-10-18/kaq/Ai-security-check/latest-source-20261031/src/security_runtime/host_events.py:74)，NormalizedHostEvent.sequence_identity 字段初始化处。

**问题**：扫描器报告 return 出现在函数外；其提供的片段实际为 default_factory 的 lambda 表达式，未提供其他说明。

**可能影响**：如果存在真实 Python 语法错误，可能影响模块加载；这条候选本身尚未证明该条件。

**建议修复**：先核对规则解释和定位，再决定排除候选或修复具体语法，不直接删除字段初始化。

**尚未确认**：本批次未做 Agent 复核，尚未确认规则命中成立。

