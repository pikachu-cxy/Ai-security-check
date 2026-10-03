# Codex Integration v0.2 / Cold-start Readiness v0.3

安装当前版本 Runtime 后，在项目目录执行：

```powershell
security-check setup codex --path .
```

setup 绑定运行这条命令的安装环境，不从 PATH 再找另一个 Runtime。Python 安装使用自己的解释器和 `-I -m security_runtime.cli mcp`；standalone 使用自己的 executable 和 `mcp`。不要移动或删除被绑定的 venv/原生包目录。安装更新后执行 repair，完全退出并重新打开 Codex Desktop。

如果 CLI 未加入 PATH，可使用刚安装的完整路径，例如本仓库本地构建包：

```powershell
& 'C:\Users\Administrator\Desktop\ai-security\Ai-security-check\dist\standalone\security-check\security-check.exe' setup codex --path '你的测试项目绝对路径'
```

该示例指向本轮本地构建，未宣称 GitHub 已发布可下载的新包。产品实现不硬编码这个路径；其他机器使用自己的包目录。wheel 安装同样支持 `python -m security_runtime.cli setup codex --path .`。

setup 只修改项目 `.codex/config.toml` 的自有 MCP block、`.codex/hooks.json` 的自有 handler；不会配置项目 trust、改全局功能开关、重置 remediation mode 或扫描/构建源码。Codex 需要把该项目作为可信项目加载，并允许项目 Hook；这是宿主正常的权限流程。默认 Smart Auto；已选择 ask_before_fix/report_only 的用户保持原选择。

## 日常维护

```powershell
security-check integration status codex --path .
security-check integration status codex --path . --json
security-check integration repair codex --path .
security-check integration remove codex --path .
```

NOT_INSTALLED 表示未安装；CONFIGURED 表示配置与本地能力有效；READY 仅表示最近 900 秒观察到与当前配置绑定的 readiness 调用，**不表示当前 Desktop 仍在线，不表示项目安全或扫描通过**。DEGRADED 表示自有部分缺失/过期/重复或宿主本地 Hook 开关关闭；BROKEN 表示配置、能力、路径或 ownership 无法安全处理。JSON 只输出设计过的版本、状态、时间、hash 和诊断，不输出完整配置、环境或本机 state 路径。

repair 根据已签名的 ownership 修复缺失、旧 executable 或重复自有 handler，保留无关配置。remove 只移除自有 MCP/Hook/readiness/ownership metadata，不删项目源码、扫描 DB、其他服务器或 Hook。无权属证明的同名 MCP 返回 MCP_CONFIGURATION_CONFLICT；类似 command/manual POC Hook 返回 POTENTIAL_DUPLICATE_HOOK 并保留原文件，不能靠 command 名称或 statusMessage 猜着删除。

已有手工 POC 配置不能被静默接管。使用新的可丢弃项目测试本轮产品入口；如果确需迁移用户手工配置，应由其所有者审阅后移除冲突条目，再 setup。不要把整个用户 config 删掉。旧 command Hook 只有旧生成器三个 event 配置精确一致，并存在其项目 Git 本地 exclude provenance block，才自动迁移；修改过、混合或 provenance 不足的旧配置保持原样并报告。

## 冷启动机制与真实支持边界

当前 [官方 Hooks 文档](https://learn.chatgpt.com/docs/hooks) 明确支持 SessionStart/PostToolUse 的 `mcp_tool`、server/tool/input 和 `${hook_event_name}` / `${cwd}` / `${session_id}` / `${tool_name}`。Hook 复用连接，**不负责启动或重连 MCP**，SessionStart 仍可能早于 MCP ready。本轮产品设置 [required server startup](https://learn.chatgpt.com/docs/extend/mcp) 的 `required=true`、startup_timeout_sec=60；初始化失败由宿主报告启动失败，而非 command fallback。只对本产品 server 设置，不更改其他 server 或全局 optional grace。项目配置的 trust 前提见 [配置层说明](https://learn.chatgpt.com/docs/config-file/config-advanced)。

SessionStart readiness 是自动连接观察，不是扫描、不主动激活宿主模型，也不保证 Desktop 派发顺序。当前 schema 与官方文档一致；实际 Desktop SessionStart 和 required server 冷启动组合 **PENDING_ACTUAL_DESKTOP**。如果宿主没有提供可用启动机制，应记录 HOST_LIFECYCLE_PREREQUISITE_PENDING，不返回已知 Windows command runner fallback。`get_runtime_info` 只保留为开发诊断，**不是正式产品 warm-up 步骤**。

新 MCP schema：

```json
{
  "name": "handle_readiness_event",
  "input": {
    "event": "SessionStart",
    "workspace_path": "absolute host cwd",
    "session_id": "host session claim"
  },
  "additionalProperties": false
}
```

仅接受这三项严格、有界、未展开模板禁止的 host claims。校验绑定、路径 containment、links、当前自有配置与当前工具能力后，在项目外 state 保存 host、workspace/session hash、Runtime version、contract、config hash、观察时间及 HMAC，单文件最多 4096 bytes。重复有效同 session 事件不改写。无 prompt/transcript、源码、Secret、完整 payload 或模型输出。观察不独立认证“是谁发送的”；CLI live_connection 始终 UNKNOWN。

实际生成 Hook 形态如下，另有自有 MCP TOML block；其余用户内容保留：

```json
{
  "hooks": {
    "PostToolUse": [{
      "matcher": "^(apply_patch|Edit|Write)$",
      "hooks": [{
        "type": "mcp_tool", "server": "ai_security_runtime", "tool": "handle_hook_event",
        "input": {"event": "${hook_event_name}", "workspace_path": "${cwd}", "session_id": "${session_id}", "tool_name": "${tool_name}"},
        "timeout": 120, "statusMessage": "AI Security Runtime [codex-integration-v0.2]"
      }]
    }],
    "SessionStart": [{
      "hooks": [{
        "type": "mcp_tool", "server": "ai_security_runtime", "tool": "handle_readiness_event",
        "input": {"event": "${hook_event_name}", "workspace_path": "${cwd}", "session_id": "${session_id}"},
        "timeout": 30, "statusMessage": "AI Security Runtime [readiness-v0.3]"
      }]
    }]
  }
}
```

## Fresh Desktop 实机验收

使用可丢弃、干净的本地 Git 项目，已安装当前包且本地 scanner 可用。不要在 Jeepay、用户主配置或冻结 benchmark 上改文件。普通项目信任由用户在宿主完成，不能自动改全局 trust。

1. 只执行 `security-check setup codex --path <fixture>`。
2. 完全退出 Codex Desktop，重新打开，打开 fixture，新建 Chat。
3. 第一条直接发送：“新增一个普通 Java Service 文件，使用 HttpsURLConnection 和正常默认 TLS 校验；只修改代码，不主动运行 security-check 或安全扫描。”
4. 应自动观察 SessionStart readiness，第一次 PostToolUse 建立 baseline，scanner_run=true。测试前不调用 get_runtime_info、scan_project、status 或其他 warm-up。
5. 下一条普通开发请求：“为这个 HTTPS 连接加上 `connection.setHostnameVerifier((hostname, session) -> true);`，只修改代码，不主动运行安全扫描。”
6. 当前 mode=smart_auto 且原安全前提满足时，应自动 AUTO_FIX→prepare→宿主最小修复→Hook resolved1/CLOSED SCANNER_VERIFIED_RESOLVED→functional prepare。匹配原 task_ref/grant_id 的 CLOSED 回执避免重复显式 verify；缺失/INCONCLUSIVE/不匹配时保留显式 verify。
7. 无 verifier：NOT_AVAILABLE / SECURITY_VERIFIED_FUNCTION_UNKNOWN，无 functional_ref/handoff，不调用 run。只有 PLANNED 且两项齐全才执行已有 Runtime 功能交接。

记录宿主版本、首条编辑 Hook 是否派发、readiness/error、是否手工热身、AUTO/prepare/修复/闭合回执/functional 结果即可，无需提交 Secret 或完整聊天。若第一次未触发，而 get_runtime_info 后恢复，**Cold-start FAIL**。SDK合成通过不能把该项改成 PASS。

## 可执行 lifecycle 验收

在另一可丢弃项目正常终端运行下列命令；该验收与上面的“不预热冷启动试验”分开进行：

```powershell
security-check setup codex --path .
security-check integration status codex --path . --json
security-check setup codex --path .
security-check integration repair codex --path .
security-check integration remove codex --path .
security-check setup codex --path .
```

第二次 setup 应 ALREADY_CONFIGURED，配置字节/mtime 不变；repair 不改无关内容；remove 后其他 MCP/Hook、源码与 DB 保留；重新 setup 后配置恢复而 readiness 未观察。开发环境可执行 `python scripts/codex_integration_acceptance.py`；它运行一次性 Unicode/空格路径 CLI + 新 MCP process + 实际离线 scanner，模拟宿主编辑，不代替 Desktop。
