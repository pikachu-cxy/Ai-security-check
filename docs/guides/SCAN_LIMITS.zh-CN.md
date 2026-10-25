# 自定义扫描枚举限制

默认目录深度为 **32 层**，文件数量上限为 **10,000 个**，目录数量上限为
**2,000 个**，单文件大小上限为 **1,000,000 字节**。

## 配置文件

在用户级 Runtime 状态目录中创建 `scan-limits.toml`：

- macOS/Linux 默认：`~/.local/state/ai-security-runtime/scan-limits.toml`。
- Windows 默认：`%LOCALAPPDATA%/AI Security Runtime/scan-limits.toml`。
- 已设置 `SECURITY_RUNTIME_STATE_DIR` 时，使用该目录。
- macOS/Linux 已设置 `XDG_STATE_HOME` 时，默认目录改为其下的 `ai-security-runtime`。

```toml
[discovery]
max_depth = 32
max_files = 10000
max_directories = 2000
max_file_size = 1000000
```

也可以通过环境变量 `SECURITY_RUNTIME_SCAN_LIMITS_FILE` 指定配置文件的绝对路径。
不读取待扫描项目内的同名文件，避免项目内容改变用户的扫描保护设置。

所有值必须为正整数，不能用 `0` 关闭限制。未知配置项、错误类型、文件不可读、
格式错误或超过 64 KiB 都会明确报错，不会悄悄使用另一套配置。

## 环境变量覆盖

| 配置项 | 对应环境变量 | 单位 |
| --- | --- | --- |
| `max_depth` | `SECURITY_RUNTIME_MAX_DEPTH` | 相对项目根目录的层数，根目录为 0 |
| `max_files` | `SECURITY_RUNTIME_MAX_FILES` | 文件条目数 |
| `max_directories` | `SECURITY_RUNTIME_MAX_DIRECTORIES` | 目录数，包括项目根目录 |
| `max_file_size` | `SECURITY_RUNTIME_MAX_FILE_SIZE` | 字节 |

优先级为：内部显式参数 > 环境变量 > 用户配置文件 > 内置默认值。
环境变量必须由运行 CLI/MCP 的进程继承；修改终端环境不会改变已运行的 MCP 进程。
修改环境变量后需重连 MCP；修改 TOML 文件后，下次扫描读取新值，不改变进行中的扫描。

## 超限时 agent 会收到什么

例如文件数量限制设为 10,000，枚举时至少发现 10,001 个文件，返回内容包括：

```json
{
  "status": "INCONCLUSIVE",
  "reason_code": "TARGET_DISCOVERY_LIMIT_EXCEEDED",
  "failure_stage": "TARGET_DISCOVERY",
  "coverage": "UNKNOWN",
  "scanner_run": false,
  "source_modified": false,
  "security_proof": false,
  "limit_kind": "max_files",
  "limit": 10000,
  "observed": 10001,
  "observed_is_lower_bound": true,
  "message": "Scan target discovery failed. Detected more than 10000 files.",
  "configuration": {
    "environment_variable": "SECURITY_RUNTIME_MAX_FILES",
    "file_key": "discovery.max_files"
  }
}
```

实际响应还包含具体 `detail`、处理建议 `remediation` 和可用的触发目录相对路径。
`observed_is_lower_bound=true` 表示枚举提前终止，只能确认至少发现这些文件，
不是项目最终总数。目录深度、目录数量和文件大小超限也分别返回对应限制与观测值。
CLI 的 JSON 模式返回相同诊断并以退出码 2 结束，MCP 将这些信息传给 agent。

超限后不会执行漏洞规则，不会只扫描前 N 个文件，也不会自动放宽限制。
配置错误使用 `TARGET_DISCOVERY_CONFIG_INVALID`，可与资源超限区分。

## 范围说明

此处控制扫描目标枚举，不是漏洞分析的调用链深度。递归枚举先排除默认生成/依赖目录，
但文件总数在识别并排除二进制文档前计数；显式文件列表不受递归目录深度限制。
这些设置不会绕过 Hook、任务快照、扫描引擎、证据传输的独立资源限制。
