# Codex Integration / First-run Baseline Seed + Trust UX v0.1

安装当前版本 Runtime 后，在项目目录执行：

```powershell
security-check setup codex --path .
```

setup 绑定运行这条命令的安装环境，不从 PATH 再找另一个 Runtime。Python 安装使用自己的解释器和 `-I -m security_runtime.cli mcp`；standalone 使用自己的 executable 和 `mcp`。不要移动或删除被绑定的 venv/原生包目录。安装更新后执行 repair，完全退出并重新打开 Codex Desktop。

如果 CLI 未加入 PATH，可使用刚安装的完整路径，例如本仓库本地构建包：

```powershell
& 'C:\Users\Administrator\Desktop\ai-security\Ai-security-check\dist\standalone-baseline-seed\security-check\security-check.exe' setup codex --path '你的测试项目绝对路径'
```

该示例指向本轮本地构建，未宣称 GitHub 已发布可下载的新包。产品实现不硬编码这个路径；其他机器使用自己的包目录。wheel 安装同样支持 `python -m security_runtime.cli setup codex --path .`。

setup 修改项目 `.codex/config.toml` 的自有 MCP block、`.codex/hooks.json` 的自有 handler，然后执行一次有界、离线的 Semgrep/Gitleaks quick 基线检查。检查不调用 AI、不修改源码、不构建或运行项目测试、不联网、不下载引擎、不授权修复。已有发现属于 PRE_EXISTING_BASELINE。确认输出 Local Baseline READY；失败时 Integration CONFIGURED 与 baseline INCONCLUSIVE 分开，overall DEGRADED。

还有一次 Codex 宿主审批：打开该项目，完成正常项目 trust，Review & Allow AI Security Runtime Hooks。然后完全退出并重开 Codex，正常编码。Runtime 不读取/改写 Codex 私有信任数据库，不绕过审批；`hook_trust=HOST_MANAGED_UNKNOWN` 不等于用户拒绝。无需 get_runtime_info、手工 scan 或 repair 热身。默认 Smart Auto；已有 ask_before_fix/report_only 选择保持。

workspace seed 在项目外自有 state 中 HMAC 签名、原子写入（≤2MB），复用 HookSnapshot safe projection：dirty snapshot digest/paths、family counts/coordinates、scan id、coverage/capability/scanner proofs。绑定 workspace、baseline/Hook schema、Runtime 版本、first-party pack/catalog checksum、固定 scanner versions 和当前已签名 integration/config。setup 全文件 inventory ≤1000 files/20MB/单文件1MB，扫描阶段60秒 cooperative deadline，加原有 Git/process/output 上限；只保存 metadata，不保存源码片段、Secret、prompt/transcript。空文件范围允许空比较基线；非空必须完整完成请求的 quick capabilities，SCOPED 仅表示无适用 SAST 的范围，不能冒充项目 FULL 安全覆盖。

首次 session state 缺失时用有效 seed；新文件与 setup 后变化正常参加比较，不因 snapshot 不同作废。Hook 扫当前/此前 dirty paths 与已知候选路径，不每次扫描 seed 全 inventory。已有风险保持 PERSISTING，后来加入的 family 才 NEW；之后普通 session state 优先，dedupe/cooldown/single-flight/family multiset 与 coverage gating 保留。seed 缺失/过期/篡改仍保留原首次 BASELINE_ESTABLISHED 非归因语义，但当前高置信 HIGH/CRITICAL 风险明确显示 FIRST_SCAN_UNATTRIBUTED_RISK_PRESENT，不因此授权 AUTO_FIX。

## 日常维护

```powershell
security-check integration status codex --path .
security-check integration status codex --path . --json
security-check integration repair codex --path .
security-check integration remove codex --path .
```

NOT_INSTALLED 表示未安装；CONFIGURED 表示配置/本地能力和 baseline 有效；overall READY 还要求最近900秒的 readiness 观察。baseline READY 只证明后续 edit 有本地比较点，**不表示当前 Desktop 仍在线，不表示项目安全或扫描通过**。DEGRADED 也包含 baseline 缺失/过期/检查未完成；BROKEN 表示配置、能力、路径或 ownership 无法安全处理。JSON 只输出设计过的版本、状态、时间、hash 和诊断，不输出完整配置、环境或本机 state 路径。

仅 READINESS_NOT_OBSERVED 且其他配置有效时，不建议 repair：正常打开可信项目即可观察启动，不需要热身。status 另外展示 Stop Guard 是否配置。缺失自有 Stop 时 repair 可补齐；已有两事件签名 ownership 的旧产品配置可安全升级，第二次 setup 不重写文件。

setup/healthy repair 在 seed contract 仍有效时 BASELINE_READY，不重扫、不因源码变化刷新比较点。首次 setup、缺失/stale seed 或不兼容 Runtime/rule-pack/config 升级允许建立；repair 重建明确 BASELINE_REESTABLISHED（重新定义比较点，不是安全证明）。status 只读取不建 seed。repair 根据已签名 ownership 修复缺失配置，保留无关内容。remove 同时删除自有 baseline seed，不删源码、普通扫描历史/Finding DB、scanner数据库、其他服务器或 Hook；re-setup 新建 seed。无权属证明的同名 MCP 返回 MCP_CONFIGURATION_CONFLICT；类似 command/manual POC Hook 返回 POTENTIAL_DUPLICATE_HOOK 并保留原文件。

已有手工 POC 配置不能被静默接管。使用新的可丢弃项目测试本轮产品入口；如果确需迁移用户手工配置，应由其所有者审阅后移除冲突条目，再 setup。不要把整个用户 config 删掉。旧 command Hook 只有旧生成器三个 event 配置精确一致，并存在其项目 Git 本地 exclude provenance block，才自动迁移；修改过、混合或 provenance 不足的旧配置保持原样并报告。

## 冷启动机制与真实支持边界

当前 [官方 Hooks 文档](https://learn.chatgpt.com/docs/hooks) 明确支持 SessionStart/PostToolUse 的 `mcp_tool`、server/tool/input 和 `${hook_event_name}` / `${cwd}` / `${session_id}` / `${tool_name}`。Hook 复用连接，**不负责启动或重连 MCP**，SessionStart 仍可能早于 MCP ready。本轮产品设置 [required server startup](https://learn.chatgpt.com/docs/extend/mcp) 的 `required=true`、startup_timeout_sec=60；初始化失败由宿主报告启动失败，而非 command fallback。只对本产品 server 设置，不更改其他 server 或全局 optional grace。项目配置的 trust 前提见 [配置层说明](https://learn.chatgpt.com/docs/config-file/config-advanced)。

SessionStart 仍只做 readiness/binding 观察，不扫描或激活模型。最新 disposable Desktop 反馈：第一次安全编辑没有 Runtime Hook 记录，第二次危险编辑是第一次有效 Hook，返回 BASELINE_ESTABLISHED / NEW0 / NONE。这是 USER_REPORTED FIRST_RUN_TRUST_GAP，不足以断言用户拒绝了 trust；此前 readiness/lifecycle PASS 保留。新 seed 的 fresh Desktop 与 Stop 自然继续仍 PENDING_ACTUAL_DESKTOP，SDK/native 不能替代。`get_runtime_info` 只保留开发诊断。required=true 和三个 Hook 定义原样保留。

三个生成定义视为 Free v1 稳定 Host Hook ABI，包括 matcher/tool/input/timeout/结构，以及目前版本样式的 statusMessage。它们不是每轮升级的版本标签，不随内部 Runtime 版本或文案变化；与本轮起点 exact definition 相同。官方要求对非托管 Hook 的当前定义 hash 审批，除安全修复或 Host contract 变化外保持定义稳定。Runtime 不猜测 Host 私有 hash 算法或当前 trust。

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

本机当前原生包可用以下 PowerShell 命令准备一次性项目（不安装依赖；setup 本身执行离线基线检查）：

```powershell
$trial = Join-Path $env:TEMP ('RuntimeSeedTrial-' + (Get-Date -Format 'yyyyMMddHHmmss'))
New-Item -ItemType Directory -Path $trial | Out-Null
git -C $trial init
Set-Content -LiteralPath (Join-Path $trial 'README.md') -Value 'Disposable baseline seed trial.'
git -C $trial add README.md
git -C $trial -c user.name=RuntimeTrial -c user.email=trial@example.invalid commit -m baseline
& 'C:\Users\Administrator\Desktop\ai-security\Ai-security-check\dist\standalone-baseline-seed\security-check\security-check.exe' setup codex --path $trial
$trial
```

先确认 setup 输出 baseline READY，再在 Codex 打开 fixture，Review & Allow hooks一次，完全退出/重开并新建 Chat。不要先 status、get_runtime_info、scan_project 或手工 reconnect；信任审批由用户在宿主完成，不使用 bypass flag。

1. 只执行 setup，确认 Local Baseline READY。
2. 打开 fixture、Review & Allow Hooks一次，完全退出 Codex Desktop，重开 fixture/新 Chat。
3. 第一条直接发送：“新增一个普通 Java Service 文件，使用 HttpsURLConnection 和正常默认 TLS 校验；只修改代码，不主动运行 security-check 或安全扫描。”
4. 首次有效 PostToolUse 必须使用 baseline_source=SETUP_SEED / baseline_available=true。可在另一 fresh fixture 故意让安全编辑的 PostToolUse 完全缺失，安全文件写好后才开始下一条危险编辑；不要用 Runtime SessionStart/scan 制造替代 baseline。
5. 下一条普通开发请求：“为这个 HTTPS 连接加上 `connection.setHostnameVerifier((hostname, session) -> true);`，只修改代码，不主动运行安全扫描。”
6. 即使第一次安全 Hook 缺失，第二次危险编辑的首有效 Hook 仍应 SETUP_SEED / NEW1 / AUTO_FIX（原安全前提满足）。随后自然 prepare→宿主最小修复；未 prepare 而准备结束时原 Stop fallback继续，同 grant最多两次。用户不输入修复/批准/安全提示。最终 resolved1/CLOSED SCANNER_VERIFIED_RESOLVED→原 functional prepare。匹配回执避免重复显式 verify；缺失/INCONCLUSIVE/不匹配保留显式 verify。
7. 无 verifier：NOT_AVAILABLE / SECURITY_VERIFIED_FUNCTION_UNKNOWN，无 functional_ref/handoff，不调用 run。只有 PLANNED 且两项齐全才执行已有 Runtime 功能交接。

另用独立 fixture，在 setup 前已有同一危险代码：首次 Hook 应 PERSISTING1 / NEW0 / NONE，不自动归因为 AI。记录 baseline.status/source、首次安全 Hook是否缺失、首有效 Hook 状态/new、AUTO_FIX、natural continuation、Stop/count、prepare、secure edit、resolved、security verification、functional prepare。无需 Secret/完整聊天；SDK合成通过不能把 Desktop 模型继续写成 PASS。

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
