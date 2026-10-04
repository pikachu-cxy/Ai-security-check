# Codex Integration v0.2 / Auto Remediation Continuation Guard v0.1

安装当前版本 Runtime 后，在项目目录执行：

```powershell
security-check setup codex --path .
```

setup 绑定运行这条命令的安装环境，不从 PATH 再找另一个 Runtime。Python 安装使用自己的解释器和 `-I -m security_runtime.cli mcp`；standalone 使用自己的 executable 和 `mcp`。不要移动或删除被绑定的 venv/原生包目录。安装更新后执行 repair，完全退出并重新打开 Codex Desktop。

如果 CLI 未加入 PATH，可使用刚安装的完整路径，例如本仓库本地构建包：

```powershell
& 'C:\Users\Administrator\Desktop\ai-security\Ai-security-check\dist\standalone-continuation\security-check\security-check.exe' setup codex --path '你的测试项目绝对路径'
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

仅 READINESS_NOT_OBSERVED 且其他配置有效时，不建议 repair：正常打开可信项目即可观察启动，不需要热身。status 另外展示 Stop Guard 是否配置。缺失自有 Stop 时 repair 可补齐；已有两事件签名 ownership 的旧产品配置可安全升级，第二次 setup 不重写文件。

repair 根据已签名的 ownership 修复缺失、旧 executable 或重复自有 handler，保留无关配置。remove 只移除自有 MCP/Hook/readiness/ownership metadata，不删项目源码、扫描 DB、其他服务器或 Hook。无权属证明的同名 MCP 返回 MCP_CONFIGURATION_CONFLICT；类似 command/manual POC Hook 返回 POTENTIAL_DUPLICATE_HOOK 并保留原文件，不能靠 command 名称或 statusMessage 猜着删除。

已有手工 POC 配置不能被静默接管。使用新的可丢弃项目测试本轮产品入口；如果确需迁移用户手工配置，应由其所有者审阅后移除冲突条目，再 setup。不要把整个用户 config 删掉。旧 command Hook 只有旧生成器三个 event 配置精确一致，并存在其项目 Git 本地 exclude provenance block，才自动迁移；修改过、混合或 provenance 不足的旧配置保持原样并报告。

## 冷启动机制与真实支持边界

当前 [官方 Hooks 文档](https://learn.chatgpt.com/docs/hooks) 明确支持 SessionStart/PostToolUse 的 `mcp_tool`、server/tool/input 和 `${hook_event_name}` / `${cwd}` / `${session_id}` / `${tool_name}`。Hook 复用连接，**不负责启动或重连 MCP**，SessionStart 仍可能早于 MCP ready。本轮产品设置 [required server startup](https://learn.chatgpt.com/docs/extend/mcp) 的 `required=true`、startup_timeout_sec=60；初始化失败由宿主报告启动失败，而非 command fallback。只对本产品 server 设置，不更改其他 server 或全局 optional grace。项目配置的 trust 前提见 [配置层说明](https://learn.chatgpt.com/docs/config-file/config-advanced)。

SessionStart readiness 是自动连接观察，不是扫描、不主动激活宿主模型，也不保证 Desktop 派发顺序。最新用户实机已确认无 warm-up 的第一次普通编辑触发 Hook、READINESS_OBSERVED / overall READY 及安装生命周期 **USER_REPORTED PASS**。最新失败是 AUTO_FIX 已发出但 Host 未调用 prepare_task_fix；本轮仅增加 Stop fallback，新 Stop 的真实 Desktop 自动继续仍 **PENDING_ACTUAL_DESKTOP**。`get_runtime_info` 只保留为开发诊断，不是产品 warm-up 步骤。保留 required=true、SessionStart 和现有 PostToolUse。

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
    }],
    "Stop": [{
      "hooks": [{
        "type": "mcp_tool", "server": "ai_security_runtime", "tool": "handle_stop_event",
        "input": {"event": "${hook_event_name}", "workspace_path": "${cwd}", "session_id": "${session_id}", "stop_hook_active": "${stop_hook_active}"},
        "timeout": 30, "statusMessage": "AI Security Runtime [continuation-guard-v0.1]"
      }]
    }]
  }
}
```

## Fresh Desktop 实机验收

使用可丢弃、干净的本地 Git 项目，已安装当前包且本地 scanner 可用。不要在 Jeepay、用户主配置或冻结 benchmark 上改文件。普通项目信任由用户在宿主完成，不能自动改全局 trust。

本机当前原生包可用以下 PowerShell 命令准备一次性项目（不安装依赖、不扫描）：

```powershell
$trial = Join-Path $env:TEMP ('RuntimeStopTrial-' + (Get-Date -Format 'yyyyMMddHHmmss'))
New-Item -ItemType Directory -Path $trial | Out-Null
git -C $trial init
Set-Content -LiteralPath (Join-Path $trial 'README.md') -Value 'Disposable Stop trial.'
git -C $trial add README.md
git -C $trial -c user.name=RuntimeTrial -c user.email=trial@example.invalid commit -m baseline
& 'C:\Users\Administrator\Desktop\ai-security\Ai-security-check\dist\standalone-continuation\security-check\security-check.exe' setup codex --path $trial
$trial
```

这是新 fixture 的唯一安全产品命令。完全重开 Desktop 后，在输出的目录中打开可信项目并新建 Chat；不要先 status、get_runtime_info、scan_project 或手工 reconnect。项目和 Hook 的正常宿主 trust review 仍由用户完成。

1. 只执行 `security-check setup codex --path <fixture>`。
2. 完全退出 Codex Desktop，重新打开，打开 fixture，新建 Chat。
3. 第一条直接发送：“新增一个普通 Java Service 文件，使用 HttpsURLConnection 和正常默认 TLS 校验；只修改代码，不主动运行 security-check 或安全扫描。”
4. 第一次 PostToolUse 建立 baseline，scanner_run=true。测试前不调用 get_runtime_info、scan_project、status 或其他 warm-up；不要求模型显式回答它看到了 SessionStart。
5. 下一条普通开发请求：“为这个 HTTPS 连接加上 `connection.setHostnameVerifier((hostname, session) -> true);`，只修改代码，不主动运行安全扫描。”
6. 当前 mode=smart_auto 且原安全前提满足时，正常 AUTO_FIX→Host 自然 prepare→宿主最小修复。若 Host 准备结束且 grant 尚未 prepare，Stop 应返回 block/reason，自动继续到原 prepare handoff；同 grant 最多两次。用户不输入“修复”、不批准、不再发安全提示。最终 Hook resolved1/CLOSED SCANNER_VERIFIED_RESOLVED→原 functional prepare。匹配原 task_ref/grant_id 的 CLOSED 回执避免重复显式 verify；缺失/INCONCLUSIVE/不匹配时保留显式 verify。
7. 无 verifier：NOT_AVAILABLE / SECURITY_VERIFIED_FUNCTION_UNKNOWN，无 functional_ref/handoff，不调用 run。只有 PLANNED 且两项齐全才执行已有 Runtime 功能交接。

记录宿主版本、AUTO_FIX issued、PostToolUse natural continuation YES/NO、Stop continuation invoked YES/NO/count、prepare_task_fix called、secure edit applied、resolved_families、security verification、explicit verify deduped、functional prepare。无需提供 Secret 或完整聊天。自然继续成功时 Stop 无需阻止；SDK合成通过不能把 Desktop 模型继续写成 PASS。

## Stop contract 与安全边界

handle_stop_event 只接受必填 event:string、workspace_path:string、session_id:string、stop_hook_active:boolean，additionalProperties=false，严格类型；前三字段分别最多 32/4096/500 字符，拒绝空值、控制字符及未展开模板。claims 不独立认证宿主；workspace 必须位于连接绑定内且无链接。没有 source、prompt、transcript、command、模型输出或 Host remediation_ref 输入。

[官方 Stop 文档](https://learn.chatgpt.com/docs/hooks#stop) 的 block/reason 会自动产生 continuation prompt，不撤销已执行编辑；Stop 不用 matcher。完整 `${stop_hook_active}` 模板保持 JSON boolean。MCP Hook 复用已连接服务器，同步执行，不启动 command runner。允许结束时文本通道为 `{}`，不生成 warning。

Stop 只续用 POLICY_AUTO 的 OFFERED/AUTO_FIX 原 handoff。原签名、workspace/host/session namespace、family/task/original scan、policy/config revision、snapshot、source/preservation guard 和未消费 prepare 均须有效。原 token 仅当前连接内保留，最多32项；900秒 continuation window 到期只关闭兜底资格，不刷新/延长 grant。重连不恢复 token。独立 host_continuation_attempt_count 最多2，计数绑定原 grant/snapshot/policy/PREPARE_REQUIRED 并写入现有 HMAC record；超过记录 HOST_CONTINUATION_EXHAUSTED 并允许结束。stop_hook_active=true 且本 guard 未发出继续时不加入其他 Stop 的循环。successful prepare 后旧条件静默，不覆盖 edit/recheck/functional 阶段。

CONFIRM_REQUIRED/PENDING_CONFIRMATION、USER_CONFIRMED、DECLINED/EXPIRED/CLOSED/ESCALATED、report_only/NONE/ADVISE/MANUAL_ONLY 均不自动继续。Stop 不扫描、不 prepare、不调用模型、不修改源码、不 build、不联网、不签发 grant。原 PostToolUse AUTO guidance、interaction 和 decision:block，以及 command transport/core 均保留。

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

本轮本机已有 Desktop 使用旧原生目录，原路径重建因 DLL 锁定失败；新包使用 dist/standalone-continuation。构建脚本仅增加 workspace dist 内的可选输出目录，默认四平台 CI 路径不变；没有终止正在运行的 MCP。不要覆盖活动包，新的 fixture 使用上面的新路径。
