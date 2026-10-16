# 宿主支持与下一阶段接入

更新日期：2026-10-15。本页是宿主接入状态、代码依据和下一阶段验收的总入口。
本轮增加了 Cursor 自动连接器和隔离独立进程验收，真实新版 Cursor 模型闭环仍待完成。
当前原生包、真实桌面与发布候选结果仍以 [开发进度](DEVELOPMENT_PROGRESS.md)
及对应验收记录为准；Codex 细节见 [Codex 接入](design/CODEX_INTEGRATION.md)。

## 如何理解支持状态

配置可写、Runtime 自检通过、真实宿主调用成功、完整用户流程通过是不同证据。
平台官方提供 MCP 或 Hook，只说明存在接入通道；不证明本产品已经适配或完成桌面验收。
本页保留已记录的有限桌面验证，同时将最新候选重验、未覆盖入口和缺失能力分别列出。

| 宿主／入口 | 本产品已有实现与证据 | 当前边界 | 下一验收目标 |
| --- | --- | --- | --- |
| Codex 桌面全局接入 | 已有观测路径的桌面验证：编辑事件、改动核对、真实扫描、授权修复、精确编辑范围、扫描证明与 `CLOSED` | 不扩展为任意版本、任意模型、所有平台通过；最新冻结包另验 | 保持现有闭环作为跨宿主回归基准，重新确认个人版不展示功能验证入口 |
| Cursor 本地桌面 | 自动测试版新增用户级 MCP/六种 Hook/公共 Skill、编辑前基线、任务上下文和有限续跑；独立进程安装及 MCP 收尾通过。前期 3.22.12 Agents 探针确认上下文与 followup 通道 | 旧仅检测模式仍兼容；新版候选尚未完成真实模型风险呈现及批准修复闭环；远程、多根未支持 | 按 [Cursor 安装与测试](guides/CURSOR_INSTALL_AND_TEST.zh-CN.md) 对同一候选进行真实开发、风险选择、复查和第二模型验收 |
| WorkBuddy 桌面 | 已有项目级 `.workbuddy/mcp.json` 管理、stdio MCP 自检和测试客户端调用回归 | 测试客户端不是 WorkBuddy 桌面；没有 WorkBuddy 标准化原生事件适配，不能宣称自动检查或修复续办已验收 | 先完成真实桌面 MCP 发现、人工发起检查、风险解释、明确批准修复及原扫描器复验；再研究原生事件 |
| Qoder IDE／JetBrains／CLI／Qoder 桌面 | CLI 中接受 `qoder` 名称并提供中立手动 Hook 命令；没有已注册的 Qoder 原生事件适配或专用安装器 | 手动命令不等于宿主已接入；各入口分开验收，既有 Qoder 效果对照样本不等于本产品接入证据 | 首先选定一个入口与版本，建议从 Qoder IDE 的 MCP 和 command Hook 做探测，再实现独立适配 |
| CodeBuddy Code／IDE／插件 | CLI 中接受 `codebuddy` 名称并提供中立手动 Hook 命令；没有已注册的 CodeBuddy 原生适配或专用安装器 | CodeBuddy Code、CodeBuddy IDE／插件与 WorkBuddy 分别记录，不能共用一个“已支持”标签 | 优先选择 CodeBuddy Code 的 MCP 与 command Hook 作为独立试点；IDE／插件后续另验 |
| Generic MCP／CLI | 现有通用工具与命令入口 | 通用 MCP 不自动提供宿主生命周期、用户可见反馈或持续扫描；CLI 通过不等于桌面通过 | 作为检查服务的兼容底座，逐宿主记录实际调用证据 |

### 当前源码与测试依据

- 注册的标准化事件适配只有 Codex 和 Cursor，未实现宿主返回空能力：
  [host_event_adapters.py](../src/security_runtime/host_event_adapters.py)、
  [host_events.py](../src/security_runtime/host_events.py)。
- Cursor 旧仅检测入口保留四种事件和关闭聊天续办的能力声明。`install cursor` 使用独立自动模式，
  增加 `preToolUse` 和 `postToolUse`，复用公共任务、检查与授权服务；
  [安装连接器](../src/security_runtime/cursor_connector.py)、[自动事件](../src/security_runtime/cursor_automatic.py)、
  [任务交接](../src/security_runtime/cursor_tasks.py)、[自动模式回归](../tests/test_cursor_automatic.py)。
  安装状态仍明确标注本地测试版、真实桌面候选待验；启动上下文不作为风险送达证明。
- Cursor 的 schema、工作区锚点、会话隔离、事件生命周期、旧配置清理与不虚构反馈有回归：
  [宿主适配](../tests/test_cursor_host_adapter.py)、
  [工作区锚点](../tests/test_cursor_workspace_anchor.py)、
  [事件生命周期](../tests/test_cursor_event_lifecycle.py)、
  [能力限制](../tests/test_cursor_cleanup.py)。这些测试不替代最新桌面运行。
- 项目 MCP 注册表包含 Cursor、WorkBuddy 和通用接口：
  [integrations.py](../src/security_runtime/integrations.py)。
  [WorkBuddy 自检与测试客户端用例](../tests/test_alpha_acceptance.py)
  区分配置、自检和客户端调用，不能将用例中的 `CONNECTED` 当作实际 WorkBuddy 应用证明。
- WorkBuddy、Qoder、CodeBuddy 的中立 Hook 命令返回 `MANUAL_CONFIGURATION_REQUIRED`，
  不生成未经实现的宿主 schema：
  [hook_adapters.py](../src/security_runtime/hook_adapters.py)、
  [手动宿主回归](../tests/test_hook_adapters.py)。CLI 参数中出现名称不提升该状态。

## 官方通道调研与入口差异

以下是 2026-10-15 查阅的官方资料，仅作为下一阶段设计输入。实施时固定实际宿主版本、
入口、操作系统及文档快照；重新检查 schema 与进程执行语义。

| 平台资料 | 官方说明的可用通道 | 对本产品下一步的含义 |
| --- | --- | --- |
| [Cursor Hooks](https://cursor.com/docs/hooks)、[Cursor MCP](https://docs.cursor.com/context/model-context-protocol) | MCP 与命令 Hook；不同事件有各自输入／输出，桌面与云端生命周期不同 | 结合前期实测接入上下文及有限结束续跑；官方字段、模拟客户端与真实模型验收分别记录 |
| [Qoder IDE Hooks](https://docs.qoder.com/extensions/hooks)、[Qoder IDE MCP](https://docs.qoder.com/user-guide/chat/model-context-protocol) | IDE／JetBrains 有其 Hook 范围及 MCP；IDE 文档明确区分 CLI 等入口 | 优先固定 IDE 入口，按该入口 schema 做探测与适配，不从其他入口复制事件或返回字段 |
| [Qoder CLI Hooks](https://docs.qoder.com/cli/hooks)、[Qoder Hooks](https://docs.qoder.com/qoder/hooks) | CLI 与 Qoder 桌面另有 Hook 文档；配置兼容不代表每个入口执行同一组事件 | CLI、IDE、Qoder 桌面分别建立能力记录；配置页可见不等于实际触发 |
| [WorkBuddy MCP](https://www.codebuddy.cn/docs/workbuddy/From-Beginner-to-Expert-Guide/Function-Description/MCP-Guide) | 用户／项目 MCP 配置和界面管理 | 先验证现有项目 MCP 路径；不从同厂商 CodeBuddy 文档推导 WorkBuddy 原生 Hook 能力 |
| [CodeBuddy Code Hooks](https://www.codebuddy.ai/docs/cli/hooks)、[插件参考](https://www.codebuddy.ai/docs/cli/plugins-reference) | CodeBuddy Code 有生命周期 Hook，插件可携带 Hook 与 MCP | 可研究独立适配与交付包，但 Hook schema、shell、审批与重连行为必须在所选版本实测；不代表 CodeBuddy IDE 已验收 |

## 共享接入架构

连接层按宿主独立，公共服务与 Core 共用。当前新增 `host_connectors.py` 组合能力、
`workspace_services.py` 工厂及 `task_hook_activity.py` 任务活动记录；Codex 旧入口保留兼容。
Cursor 的配置、原始事件和输出字段留在各自连接器中，不复制扫描、策略或修复引擎：

```text
宿主原始事件 → 宿主专用输入适配与工作区／会话核对
             → HostEvent v1 → Runtime Core
             → 扫描／Finding／策略／修复授权／原扫描器证明
             → 宿主专用呈现与交接
```

MCP 提供显式查询、检查与修复工具；原生 Hook 提供可证明的生命周期触发。
两者可以互补，不能由“已连 MCP”推导“每次编辑都检查”。输入适配只解释该版本已验证的
字段和工具分类；检查真实工作区改动，不信任宿主文本宣称代码未变、已测试或已经批准。

每个适配分别记录检测、建议修复、用户可见反馈、自动续办、停止事件和安装范围。
缺少某项能力时保留明确的建议／手动流程，不使用反复 `stop` 唤醒、提示词模拟事件或
虚构 `additionalContext` 补齐。能力声明只说明传输是否可用，不授予修复、构建或联网权限。
工作区、会话、调用引用和修复证明继续由 Core 校验；明确用户选择后才进行原批准范围内的修复。

个人版宿主接入保持“检查、解释、授权修复、安全复验”的边界；不重新展示已隐藏的功能验证
邀请，不自动运行构建、测试或企业深度验证。企业任务的执行授权与结果协议另行设计。

### 下一阶段工作顺序

| 阶段 | 工作包 | 退出条件 |
| --- | --- | --- |
| 1 | 固定当前发布候选和通用宿主验收样本；重验 Cursor 已有检测路径 | 真实版本、事件、扫描器执行与反馈限制均有记录，保留既有有限验证结论 |
| 2 | Cursor 新反馈／续办能力探测和完整路径验收 | 完成实际用户可见路径或明确记录不可用；未授权不修复、复验后能正常回到原任务 |
| 3 | Qoder 选定客户端入口、完成最小接入 | 取得原始事件样例、schema、输出处理、shell／路径与权限边界依据；通过后才扩大自动适配 |
| 4 | WorkBuddy 真实 MCP 试用及 CodeBuddy 独立接入 | 两产品分别完成下表；配置、自检和实际客户端结果分开，不互相借用验收结论 |
| 5 | 再评估其他操作系统、IDE 插件、远程和多根工作区 | 有实际需求、明确边界和独立测试预算，不继承本地单根桌面的通过状态 |

接口调查和样例准备可并行；主交付顺序与近期计划一致。缺失能力按宿主降级，不用平台总标签掩盖未知。

开发工作已推进到 Cursor 自动测试版；表中的完整用户闭环和其他宿主仍按退出条件逐项验收。

## 每个宿主均需填写的验收表

每个宿主、入口、版本、操作系统与 Runtime 候选分别填一份；状态使用
`PASS`、`FAIL`、`NOT_SUPPORTED`、`NOT_RUN`，附可复核记录。
被跳过或缺少能力的项目不计为通过；只对实际覆盖范围作结论。

| 验收项 | 必须观察的事实 | 关键失败／反例 |
| --- | --- | --- |
| 安装、信任与清理 | 实际加载正确候选；保留用户原配置；重连、修复、卸载只处理本产品拥有的条目 | 配置冲突、路径含空格、旧候选、缺依赖、中断与不可信项目 |
| MCP 发现与调用 | 在真实宿主发现所需工具并成功调用；个人版不发现功能验证工具或收到推荐 | Runtime 自检／模拟客户端不能替代；缺工具准确披露，不触发自动升级或构建 |
| 工作区与会话 | 项目根、会话、调用和引用对应；本地状态不跨项目混用 | 伪造 cwd、其他会话引用、符号链接／junction、嵌套仓库、远程或多根输入 |
| 编辑与 shell 事件 | 原生文件编辑和 shell 实际改动得到核对；只读事件不重复扫描 | 重复／乱序／缺失事件、退出码 0 但无改动、先改文件再报错、大批改动 |
| 首扫与覆盖 | 原有风险、新增风险、未支持输入与未完成检查区分清楚 | 没有基线不强行归因为本次编辑；缺数据或工具不报通过 |
| 风险反馈 | 用户确实看到位置、影响、证据、未知与处理选择；反馈通道单独留证 | JSON 被忽略、提示只存在日志、原始密钥／源码泄露、重复提示或打断正常任务 |
| 批准与修复 | 明确选择对应问题后，仅修改批准范围；跨轮续办继续校验原授权 | 未授权、过期授权、跨项目引用、一次批准被扩大、修复失败后自动无限重试 |
| 原问题安全复验 | 原扫描器真实执行并验证全部原任务成员；证明与当前代码绑定 | 只凭宿主称通过、通过移动行号消警、只修一条、扫描缺口或陈旧证明 |
| 结束与后续任务 | 成功后合并安全复查结果并恢复原任务；重连与 stop 不复活授权 | 旧功能验证邀请、自动测试／构建、重复询问、stop 循环、无变化仍重复扫全库 |
| 性能、故障与数据 | 记录真实等待；检查故障可说明；本地诊断按约定脱敏 | 把模拟事件当桌面证据、漏记超时、未知当 PASS、上传未批准的业务材料 |

验收只保存必要的脱敏事件结构、版本、范围、阶段结果和证据位置。
完整聊天、用户配置、密钥及业务仓库原始数据不因完善接入文档而进入公共仓库。
