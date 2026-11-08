# 自定义配置

从 0.3.13 起，可在一份用户配置中调整开发记录容量、Agent 分析、Stop 兜底、大项目扫描限制、扫描规则与漏洞数据。未填写的字段使用默认值，升级不会覆盖已有用户配置。

## 1. 找到配置文件

| 系统 | 默认位置 |
| --- | --- |
| macOS / Linux | `~/.config/ai-security-runtime/config.toml`；设置了 `XDG_CONFIG_HOME` 时使用该目录 |
| Windows | `%APPDATA%\ai-security-runtime\config.toml` |

`SECURITY_RUNTIME_CONFIG` 可指定另一个绝对路径，必须由启动 Runtime 的环境传入。产品不会自动读取项目内的配置。普通配置文件不应使用符号链接。

先运行 `security-check development-config`，查看实际路径、来源和有效值。Mac 自动安装用户可直接执行：

```sh
RUNTIME="$HOME/.local/share/AI-Security-Runtime-install/launcher/security-check"
"$RUNTIME" development-config
mkdir -p "$HOME/.config/ai-security-runtime"
```

使用完整包时，将命令中的程序换为实际安装的 `security-check`，Windows 为 `security-check.exe`，详见[选择程序路径](./installation.md#runtime-path)。

没有文件时，可创建 UTF-8 编码的 `config.toml`，只填写要修改的字段。已有文件先备份，再修改对应配置段，**不要在末尾重复追加同名 TOML 段**。可下载<a href="../examples/config.toml" download>完整默认配置示例</a>，对照后选择需要的字段。

## 2. 开发记录、Agent 与 Stop

也可在后台产品设置中按功能分类展开修改。候选复核默认开启，业务审计默认关闭。`development.repair_recheck_enabled=false` 关闭额外修后复查；修复编辑仍按普通开发检查。`review_response_bytes` 默认 65536，允许 16384–262144 字节，控制证据和复核分页预算。

Stop 的 `wait_mode="bounded"` 默认每次等待 18 秒；可选择 `"wait_for_result"`，但仍受当前宿主 Hook 上限约束，不等于无限等待。

以下是默认设置：

```toml
schema_version = 1

[storage]
development_record_limit_enabled = true
development_max_records = 1024

[agent]
review_scanner_findings = true
audit_business_logic = false

[development]
review_response_bytes = 65536
repair_recheck_enabled = false

[development.stop_fallback]
enabled = true
wait_mode = "bounded"
native_wait_seconds = 18
wait_timeout_seconds = 120
max_continuations = 2
```

| 设置 | 用途与可选值 |
| --- | --- |
| `development_max_records` | 每个工作区开发检查存储的新记录配额，默认 1024，必须为正整数；不是文件数量。满额后拒绝新建，已有检查仍可读取和收尾，不自动删除历史，因此内部总行数可超过配额 |
| `development_record_limit_enabled` | `false` 关闭上述配额；独立数据库大小和单记录保护仍保留 |
| `review_scanner_findings` | `false` 跳过自动扫描候选与误报复核 |
| `audit_business_logic` | `false` 跳过自动业务逻辑审计 |
| Stop 的 `enabled` | `false` 关闭兜底；正常助手主动收尾仍可工作 |
| `wait_timeout_seconds` | Stop 续接总预算，1–3600 秒；不是单次 Hook 阻塞时间，也不是扫描器超时 |
| `max_continuations` | 最多续接 1–10 次；宿主自身限制可能更低。不是保证只出现一次提示 |

### 只要静态扫描，但保留 Stop 兜底

将已有对应段改成：

```toml
[agent]
review_scanner_findings = false
audit_business_logic = false

[development.stop_fallback]
enabled = true
wait_timeout_seconds = 120
max_continuations = 2
```

结果只报告扫描器静态候选，不提交 Agent 复核，也不会称为 Agent 已确认漏洞。关闭 Agent 不会自动关闭 Stop。两项 Agent 分析原本也是基于代码的静态分析，不代表执行你的业务程序。

Stop 只处理本回合已记录的修改及其续接，沿原检查提交或读取，不重扫历史任务。只读聊天不接管旧检查。失败或耗尽预算时保留未完成状态并说明原因；用户取消、宿主未发出 Hook、未观测到的文件不能保证自动补齐。读取结果不证明用户已看到报告。

## 3. 大项目扫描容量和时间

以下各段的数值必须是非负整数。**0 只关闭该项限制**；其他阶段的限制仍生效，关闭所有限制也不保证任意大项目都能完成。字节使用十进制整数，时间单位为秒。

| 配置段 | 默认字段与数值 | 控制什么 |
| --- | --- | --- |
| `[scan.discovery]` | `max_files=10000`、`max_directories=2000`、`max_depth=32`、`max_file_bytes=1000000` | 项目文件发现的数量、目录、深度与文件大小 |
| `[scan.input]` | `max_files=10000`、`max_total_bytes=128000000`、`max_file_bytes=4000000`、`max_index_bytes=8000000` | 固定扫描输入与索引容量 |
| `[scan.git]` | `timeout_seconds=10`、`max_output_bytes=4000000` | Git 查询时间与输出 |
| `[scan.execution]` | `sast_timeout_seconds=45`、`gitleaks_timeout_seconds=30`、`trivy_timeout_seconds=90`、`max_output_bytes=4000000` | 各扫描器时间与输出 |
| `[storage.explicit_scan_jobs]` | `max_records=128`、`max_total_bytes=96000000`、`max_database_bytes=128000000` | 显式扫描任务存储 |
| `[storage.scan_publication]` | `max_records=32`、`max_record_bytes=8000000`、`max_total_bytes=32000000` | 扫描发布结果存储 |

例如，仅取消发现和固定输入阶段的文件数上限：

```toml
[scan.discovery]
max_files = 0

[scan.input]
max_files = 0
```

文件大小、目录数、扫描器时间限制仍有效。超限时按诊断中指出的配置段调整，再明确提交新扫描；不能把超限当成“零风险”。降低存储配额不清理历史，已有结果仍可查询。

上述 `0` 规则不适用于 `development_max_records`、Stop 时间/次数或漏洞库刷新间隔。内存、磁盘、系统和扫描器自身限制仍存在；取消、路径归属、版本校验、禁止链接和分页不会关闭。

## 4. 自定义扫描规则

### OpenGrep 代码规则

```toml
[rules.sast]
mode = "extend"
paths = ["/absolute/path/to/my-rules"]
exclude_ids = []
```

| 模式 | 行为 |
| --- | --- |
| `builtin`（默认） | 使用随包规则，`paths` 必须为空 |
| `extend` | 在随包规则上增加指定目录中的规则 |
| `replace` | 仅使用指定目录的代码扫描规则；不关闭其他独立扫描器 |

规则目录必须为本机绝对路径，文件使用扫描器原生 YAML 格式。例如保存为 `my-rules/eval.yaml`：

```yaml
rules:
  - id: local.eval-candidate
    languages: [python]
    message: Review dynamic evaluation of this expression
    severity: ERROR
    pattern: eval($X)
```

`exclude_ids` 填实际执行规则的完整 ID。未知 ID、重复 ID、错误路径或格式会报错，不静默退回默认规则。规则目录验证仍限制最多 10000 个 YAML、每个 1 MB，与项目容量配置不同。启用自定义规则后保守地重新扫描，不复用旧扫描结果。

Windows 路径可用 TOML 单引号避免转义：`paths = ['C:\security-rules']`。不要写 `~` 代替绝对路径。

### Gitleaks 密钥规则

```toml
[rules.gitleaks]
config_path = "/absolute/path/to/gitleaks.toml"
```

留空使用原行为。配置文件必须是原生 Gitleaks TOML；需要保留其默认规则时，在该文件中加入 `[extend]` 和 `useDefault = true`。扫描使用经过校验的固定副本。

## 5. 漏洞数据库与更新

```toml
[vulnerability_data.trivy]
repositories = []
cache_dir = ""
update_mode = "auto"
update_interval_seconds = 0
stale_policy = "allow_with_gap"
```

| 设置 | 说明 |
| --- | --- |
| `repositories` | 公共 OCI 漏洞库镜像列表，空列表保留随包默认源。格式为 `registry/path:tag`，不含 `https://`、用户名密码或查询参数 |
| `cache_dir` | 本机绝对缓存目录，空字符串沿用现有环境/默认位置 |
| `update_mode` | `auto` 使用自动准备策略；`manual` 只显式更新；`offline` 连显式更新也不联网 |
| `update_interval_seconds` | 默认 0 遵循上游过期时间；正数额外要求到龄刷新，**0 不表示永不过期** |
| `stale_policy` | `allow_with_gap` 可保留旧数据并报告缺口；`require_fresh` 不允许以过期库完成依赖漏洞检查 |

```sh
security-check vulnerability-data status --json
# 需要联网；offline 模式下拒绝更新
security-check vulnerability-data update --json
```

更新失败不删除可用旧库，缺数据不等于没有漏洞。普通开发的本地复查不会仅因 `auto` 自动下载。这里配置的是 Trivy 支持的漏洞数据库来源，不支持任意 JSON/CSV 漏洞清单或新增 Trivy Rego 策略接口。规则、漏洞数据与程序版本独立记录。

## 6. 保存、验证与恢复

1. 保存文件后运行 `security-check development-config`，确认状态为 `VALID`，并核对实际路径和有效值。此命令只读，不是“应用设置”按钮。
2. 修改 TOML 无需重装或重启；新检查/新编辑批次读取新配置，已开始的批次和已提交的后台扫描保留旧快照。验证新组合请使用新聊天、新修改和新检查。
3. 未知字段、错误类型、重复 TOML 段或非法值会返回 `INVALID`，不能视为设置已生效；按报错修正，或恢复先前备份。配置文件须为 UTF-8 且不超过 64 KiB。
4. 删除某个自定义字段会恢复对应默认值。不要为调配置删除检查数据库或历史记录。

显式扫描参数优先，其次为统一配置明确填写的字段，再依次是兼容的旧环境变量、旧 `scan-limits.toml` 与默认值。配置变更参与项目扫描结果复用判断。

快速状态查询 `security-check runtime-info --fast --json` 不重新验证组件健康；首次安装或排障使用完整查询。Codex CLI 与 Cursor CLI 需要宿主支持并启用原生 Hook；Claude Code、Qoder CLI 为后续计划。详见[日常流程](./workflow.md)和[平台支持](../reference/support.md)。
