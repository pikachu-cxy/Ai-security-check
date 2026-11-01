# 用户配置与 CLI Stop 兜底

本改造保留正常的助手主动收尾；Stop 只对当前会话明确聚焦的轻量开发检查补交或提示读取结果。
不重新安装当前版本，不迁移历史任务，不自动扫描已有的遗留未收尾记录。

## 配置位置

macOS/Linux：`~/.config/ai-security-runtime/config.toml`（遵循 XDG_CONFIG_HOME）。
Windows：`%APPDATA%/ai-security-runtime/config.toml`。
可用 `SECURITY_RUNTIME_CONFIG` 指定绝对路径；没有配置文件使用默认值。
用户配置独立于工作区状态目录和版本安装目录；不会自动加载项目内的不可信设置。
完整示例见 [config.toml](examples/config.toml)。升级不得覆盖这份用户文件。

`security-check development-config` 或 MCP `get_development_config` 只读显示实际设置、路径和来源。
文件有语法错误、未知字段或错误类型时显示 INVALID，不静默关闭检查或假装生效。
检查保存配置快照；当前批次沿用快照。后续新检查或已完成后开始的新编辑批次采用最新配置。
历史记录没有配置快照时不自动被 Stop 补扫。

## 选项

| 字段 | 默认 | 说明 |
|---|---|---|
| storage.development_record_limit_enabled | true | 关闭则不限制新检查的记录数配额，独立磁盘/单记录限制保留 |
| storage.development_max_records | 1024 | 正整数；到达配额不再创建新检查，已有检查的完成记录仍可保存，因此总行数可能超过配额 |
| agent.review_scanner_findings | true | 扫描命中与误报复核 |
| agent.audit_business_logic | true | 主动分析业务逻辑与相关漏洞 |
| development.stop_fallback.enabled | true | 开启当前检查的 Stop 兜底 |
| development.stop_fallback.wait_timeout_seconds | 120 | 1–3600；一次兜底总预算，非单个 Hook 同步等待秒数 |
| development.stop_fallback.max_continuations | 2 | 1–10；有界续接，宿主本身的循环限制可能更低 |

容量下调不删除记录、不阻断历史读取；读取按分页获取，仍受数据库文件大小保护。
已有检查的交付、风险保留和继续更新可越过新增检查配额，避免满额后无法收尾。
两项 Agent 开关均关闭时只报告静态结果；状态为 SKIPPED_BY_CONFIG，不冒称已完成 AI 复核。
静态候选不依赖 Agent 提交入库；风险投影失败不重跑扫描，原始扫描结果与交付记录保留。
配置控制自动开发分析；用户另行要求专项审计仍走专项流程，不把自动模式关闭当作用户禁止一切分析。

## Stop 与两个 CLI

修改用户 TOML 无需重启宿主；`development-config` 只读展示配置，不是应用命令。
每个检查批次保存配置快照。尤其是尚未收尾的批次，后续重新开启 Stop 不会改写其关闭快照；
验证新的组合应新建检查，并核对该记录的 `effective_config`。已有记录可明确主动收尾。
只关闭两个 Agent 开关时，应保持 `[development.stop_fallback].enabled=true`，才能验收静态扫描兜底。

Stop 续接和风险接口共用报告要求：有风险时使用标题、级别/来源、位置及四段风险格式；
提交复核后从第一页重新读取最新风险与处置，按返回动作完成分页。无风险且检查完整时保持普通开发静默。
这是助手执行要求与接口流程提示，不是最终自然语言格式校验或用户阅读回执。

Codex 原生 MCP Stop 返回 `decision=block`、`reason`；命令适配入口也支持相同续接输出。
Cursor 自动命令适配对 `status=completed` 的 stop 返回 `followup_message`；aborted/error 不补交。
当前检查无更新时放行；未提交时沿原引用提交；已排队只等待；已有结果提示读取并按快照分析。
新编辑不把旧结果当作完成。续接中的新编辑不重置整体预算。预算耗尽时保留未完成状态。
Cursor 没有等同 Codex systemMessage 的独立提示通道，预算耗尽后不再强行增加 followup；诊断仍保留。
已提供结果或续接提示不等于用户已看到。无可信报告回执时保留待确认，绝不由模型伪造确认。

只有真实宿主触发且通过原有工作区、会话校验的事件进入此流程。用户中断、进程强杀、禁用 Hook、
宿主未触发事件不能保证闭环。Codex 的 Stop 是正常续接入口，不注册 Interrupt 来恢复用户取消。
不引入修复权限，不把轻量检查用于结束严格审计或原生修复。

Codex CLI 和 Cursor CLI 按原生事件协议适配；真实版本支持范围仍需各自客户端验收。
本地自动化测试验证事件输入、状态存储与响应协议，不等于已登录客户端端到端验收。
Cursor 的 Shell 事后事件可能只记录未知范围；本次不声称已新增跨命令进程常驻文件监听。
Claude Code 与 Qoder CLI 列为后续兼容计划，本期不声明支持。

参考协议：
- https://learn.chatgpt.com/docs/hooks
- https://cursor.com/docs/hooks

## 大项目扫描、规则与漏洞数据

统一配置新增 `scan`、`rules`、`vulnerability_data`，完整字段见 examples/config.toml。
所有新增容量/执行时间字段的 0 表示关闭该项产品限制；负数、布尔值、未知字段拒绝生效。
取消操作、文件归属、禁止链接、版本/签名校验和通信分页仍保留。关闭限制仍受物理内存、磁盘、
操作系统和扫描引擎自身能力约束。子进程输出分块捕获并在超过 1 MB 后落盘，解析 JSON 仍需要内存。
规则目录自身仍使用已有格式/安全验证（最多 10000 个 YAML，单文件 1 MB）；这不是项目扫描容量。

优先级为操作显式参数 > 统一配置中明确填写的字段 > 旧环境变量 > 旧 scan-limits.toml > 默认值。
没有填写的新字段保持原默认值。旧发现限制继续兼容；首次扫描提交时固定有效值，后台工作不跟随后来的
配置变化。已有开发批次沿其配置快照，新的开发批次与显式扫描读取新配置。无需为修改配置重装产品。
容量降低不清理历史数据；扫描任务的条数限制用于新建任务，已有结果仍可查询、完成。
统一配置变化参与全项目结果复用身份；自定义规则启用时保守地重新执行扫描，不复用旧扫描结果。

`rules.sast` 控制 OpenGrep/Semgrep 规则，不改变独立数据流或其他扫描器规则。
`builtin` 使用原规则；`extend` 加入 paths 的本地规则；`replace` 只使用 paths。
排除列表使用完整规则 ID；重复 ID、错误路径、错误 YAML、未知排除 ID 均报错，不回退成默认规则。
自定义规则使用现有扫描器原生 YAML，不引入另一套规则语言。文件必须由用户配置主动指定。
`rules.gitleaks.config_path` 指定原生 TOML，扫描期间使用校验后的固定副本；
若要保留其默认规则，在该 TOML 中使用 `[extend]`、`useDefault = true`。
本次不新增 Trivy 自定义 Rego 策略接口，也不支持任意漏洞 JSON/CSV 作为数据库；保留现有适配边界。

Trivy 支持修改公共 OCI 漏洞库仓库、缓存目录、自动/手动/离线更新方式、刷新间隔和过期策略。
默认行为不变：自动准备，更新失败保留旧数据库并如实提示缺口。`require_fresh` 会拒绝以过期库完成漏洞扫描，
不会把失败误报成零风险。`manual` 只允许显式更新命令联网；`offline` 禁止更新，包括手动请求。
普通开发的本地复查仍不会因为配置 auto 而自动下载。镜像地址不接受 URL 用户名密码；不要在配置里放凭据。
指定自定义 Trivy 仓库或缓存目录时，启用现有数据库内容身份校验并参与结果复用判断。
默认数据源保留原来不逐次哈希整个漏洞库的性能策略，只核对原有新鲜度边界；不能声称默认扫描做了全库内容校验。
规则、数据库和 Runtime 版本分别记录。

```sh
RUNTIME="$HOME/.local/share/AI-Security-Runtime-macos-trial/security-check"
"$RUNTIME" development-config
"$RUNTIME" runtime-info --fast --json
"$RUNTIME" vulnerability-data status --json
# 手动下载公开漏洞数据（需要联网；不会扫描或上传项目代码）
"$RUNTIME" vulnerability-data update --json
```

快速信息只读取版本和配置，明确返回 NOT_REVALIDATED，不等于组件实时可用。
完整 `runtime-info --json` 和 integration status 仍进行原校验，进度写到 stderr，stdout 保持 JSON。
Stop 与正常收尾共用风险提示：仍需决定的风险在末尾统一提供一次“修复／暂不处理”；已授权、已暂缓、
已排除或已解决的不重复问。未选择不会自动保存为暂缓，提交复核后仍从第一页重新读取。

Codex 全局配置也可快速查看（只报告文件中是否存在 MCP 条目及已保存 Hook 事件，不验证归属或连接）：

```sh
"$RUNTIME" integration status codex --scope global --fast --json
```
