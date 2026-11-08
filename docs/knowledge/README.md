# AI Security Runtime 项目字典

本知识库帮助开发者和 Agent 从需求找到代码位置，理解当前设计目的，并使用一致的实现与验收标准。范围是当前工作区源码；不是已发布产品清单，也不保存演进历史。

## 阅读入口

| 要回答的问题 | 入口 |
| --- | --- |
| 产品做什么、各层如何协作 | [架构](ARCHITECTURE.md) |
| 哪些已实现、哪些仍未验收 | [当前状态与目标](STATUS.md) |
| 我要修改什么文件、跑哪些测试 | [修改导航](CHANGE_MAP.md) |
| MCP、CLI、Hook、内部接口如何设计 | [接口设计](INTERFACES.md) |
| 对外 MCP 工具有哪些、内部操作在哪里 | [对外入口 → 内部操作 → 源码索引](MCP_CATALOG.md) |
| 某个类或函数在哪里 | [符号索引](SYMBOLS.json)，或下方查询命令 |
| 为什么采用这些边界、哪些语义必须保持 | [设计约束](DESIGN_RULES.md) |
| 新开发怎么实现、验证与交付 | [开发规范](DEVELOPMENT.md) |
| 扫描、Agent 复核和工具交互耗时 | [性能分析](PERFORMANCE.md) |
| 风险管理 Web 与并行业务审计实现与边界 | [产品开发方案](PRODUCT_ROADMAP.md) |
| 中断恢复、结果补交及性能验收 | [恢复验收](RECOVERY_ACCEPTANCE.md) |
| 中文漏洞说明与开发会话名称 | [后台展示验收](WEB_PRESENTATION_ACCEPTANCE.md) |
| 本期如何手动验收 | [验收清单](WEB_ACCEPTANCE.md) |
| 四种真实 Codex 会话验收的结果、耗时和待修问题 | [会话流程验收](FLOW_ACCEPTANCE.md) |
| 三种配置交接缺陷修复、复测和性能边界 | [三种配置修复验收](THREE_MODE_REPAIR_ACCEPTANCE.md) |
| 静态、复核、业务审计三种配置的真实开发回复与耗时 | [三种配置验收](THREE_MODE_ACCEPTANCE.md) |
| 修复后的真实开发、并行审计、修复交接与安装状态 | [修复验收](FLOW_REPAIR_ACCEPTANCE.md) |
| 上述验收缺陷如何修复、如何控制耗时与验收 | [会话流程修复方案](FLOW_REPAIR_PLAN.md) |

## 本期收尾修复

中文报告、用户处置、审计状态与等待设置见 [验收修复](UAT_REPAIR_ACCEPTANCE.md)，包含功能结果、宿主限制和全部性能样本。

## 快速定位

在仓库根目录，使用已有 Python 3.12+ 环境：

```powershell
python scripts/maintenance/knowledge_index.py --find DevelopmentCheckService
python scripts/maintenance/knowledge_index.py --find launcher
python scripts/maintenance/knowledge_index.py --find submit_development_review
```

查询通过 AST 读取源码，不导入或运行 Runtime，不连接 MCP、不扫描项目。先定位符号，再阅读函数、调用方和对应测试；不要把名称匹配当成调用链证明。

## 事实来源和更新规则

当前用户要求决定任务范围；实际源码、类型契约和同版本测试决定实现行为；本知识库负责解释和导航。运行中工具 schema 决定当前连接能接受的参数。发现不一致时先核对源码与构建身份，再更新文档，不按过期文字改坏实现。

人工维护的页面解释职责、目的和验收边界；`MCP_CATALOG.md` 与 `SYMBOLS.json` 由 [维护脚本](../../scripts/maintenance/knowledge_index.py) 生成，不手改。接口或符号变化后重新生成，`--check` 验证目录是否过期。

符号索引同时记录各模块的 SHA-256，函数体改变但行号未变时也能检测过期。索引对应生成时的工作区源码（包括未提交改动），不表示这些源码已随知识库提交、安装或发布。MCP 目录的底层声明由 AST 提取；对外发现数量说明须同时核对全局注册逻辑、契约测试和实际 `tools/list`，不能靠装饰器数量推导。

本知识库不要求后续 Agent 全量扫描代码。索引生成是静态文档维护，不是安全扫描、依赖安装或测试执行。第三方规则内容、构建目录和测试临时副本不进入符号索引。
