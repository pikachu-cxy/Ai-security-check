# Smart Auto Remediation v0.1

Runtime 0.3.1、`developer-guidance-v0.3` 保持；新增可选 feature `smart_auto_remediation: v0.1`。本轮只授权局部 JDK HTTPS 连接的 trust-all hostname verifier 修复。Runtime 决策和验证，宿主修改文件。

## 决策与身份

`RemediationDecision`：

```json
{
  "action": "AUTO_FIX",
  "reason_code": "SAFE_DETERMINISTIC_FIX",
  "finding_family": "eq-v1.<hash>",
  "category": "code",
  "finding_policy": "ACTIONABLE",
  "policy_source": "DETERMINISTIC_LOCAL_TLS_INVARIANT",
  "max_attempts": 2,
  "verification_required": true,
  "attempt_count": 1,
  "feedback_required": true,
  "production_reachability": "UNKNOWN",
  "prepare": {"mcp_tool": "prepare_task_fix", "arguments": {"task_ref": "task-v1.<bound identity>", "remediation_ref": "rem-v1.<opaque grant>"}},
  "verify": {"mcp_tool": "verify_task_fix", "arguments": {"task_ref": "task-v1.<same identity>", "remediation_ref": "rem-v1.<same grant>"}}
}
```

支持 NONE、ADVISE、AUTO_FIX、CONFIRM_REQUIRED、MANUAL_ONLY、ESCALATE。只有 Runtime 生成的有效 AUTO_FIX grant 授权局部修改，源文件/模型/Scanner 文字不授权。固定 task_ref 继续绑定 workspace、原 scan 和精确成员；grant 另绑定 workspace/session/family/attempt，不能用 T01 或最新结果换对象。失效、证据变化或连接中断时 fail closed。

## 默认模式

用户状态目录（`SECURITY_RUNTIME_STATE_DIR` 或既有默认状态目录）的 `remediation.json`：

```json
{"remediation":{"mode":"smart_auto"}}
```

没有配置时默认 smart_auto；无效/过大/链接配置禁用自动授权。ask_before_fix 把可自动项变为 CONFIRM_REQUIRED；report_only 只报告。项目配置不覆盖这个用户选择。

已安装 CLI 可执行：

```powershell
security-check remediation status
security-check remediation configure --mode smart_auto
security-check remediation configure --mode ask_before_fix
security-check remediation configure --mode report_only
```

fixture 使用独立状态目录，若要调整其模式，先在同一 shell 指定该目录。不要修改源码来改变用户模式。

## eligibility 的真实边界

仅 `ai-security.java.trust-all-hostname`；原 Semgrep、first-party pack/engine/version/checksum 身份、FULL 当前 Hook scope 和 EXECUTED CODE_SAST 必须存在。NEW family 单 occurrence、现有单成员任务、HIGH confidence/HIGH severity、局部 JDK 类型及安装位置全部可核对。

第一版只接受如下独立语句，且前文有明确 JDK URL/HttpsURLConnection 的 import 或全限定名和局部构造，没有重赋值、类型遮蔽、全局 TLS 修改或多个安装位置：

```java
HttpsURLConnection connection = (HttpsURLConnection) new URL(url).openConnection();
connection.setHostnameVerifier((hostname, session) -> true);
```

NEW 未审阅候选在这个极窄的本地 TLS 不变量有确定依据时，独立 RemediationPolicy 可以给出 **本地修复 policy ACTIONABLE**。这不是把 AI verdict/exploitability 或原 triage priority 改成已确认；原 Raw、REVIEW、STALE、FAILED、risk、覆盖均保留。已有有效 REVIEW/SUPPRESSED/LOWER_PRIORITY 不会被这个评估提升。生产使用、可达性、业务兼容性保持 UNKNOWN；没有 LLM 决定 eligibility。

允许删除该独立 bypass 语句以恢复 JDK 默认校验，或在同一 receiver 恢复 JDK default verifier；其他 Java tokens/字面量及其他文件必须保留。匿名实现、独立 verifier 类、混合 trust-manager 任务、类型/证据不明确、Secret/依赖/IAM/IaC/业务语义都不自动修。

目标最多 32 KiB；独立保留性证明最多 200 文件、200 目录、401 entries、2 MB（单个非目标文件最多 512 KiB）。包含 ignored/untracked 配置与文件，排除根 `.git`，拒绝链接和特殊文件；只持久化 HMAC。大项目超限如实 ADVISE，不声称全面支持。状态/DB/config 必须在 workspace 外，原有 Hook snapshot/cooldown 不变。

## 宿主衔接与防循环

`HookCoordinator → RemediationService → RemediationPolicy → Codex transport`。适配器只投影 Runtime 决策，AUTO_FIX 在 text 和 structuredContent 一致返回 `decision: "block"`、固定 `reason`、`systemMessage`、PostToolUse `hookSpecificOutput.additionalContext`。依据 [当前官方 Hooks 文档](https://learn.chatgpt.com/docs/hooks)：block 用反馈替换已完成的 tool result 并继续 Agent，不撤销文件修改；Code mode 的嵌套 tool promise 会在副作用后 reject。真实宿主如何继续仍需本轮实机验收。

宿主保留 grant，调用现有 `prepare_task_fix`（只读受限脱敏/UNTRUSTED_CODE packet），实施最小局部修改。下一次 Hook 对同一 grant 使用现有 TaskFixService/VerificationService 自动复查，随后宿主调用现有 `verify_task_fix`。两工具仅新增可选 remediation_ref，原显式修复流不变。自动复查和显式复查各运行一次，不拿 Hook 的“没 Finding”代替验证。

第一次授权计 attempt 1；已准备的编辑仍存在时发 attempt 2；第二次仍在则 ESCALATE，不再 block。重复 snapshot 不重复授权，成功 CLOSED、无关编辑不重开。最多 16 families/session、64 sessions/workspace、262144 字节/state；HMAC 签名、OS lock、原子写。损坏状态不重置预算，满容量不自动淘汰活跃 session。state 保存 token hash、family/session hash、attempt、snapshot、action、verification、固定任务引用与保留性 HMAC，不保存源码、prompt、Secret 原值或匹配内容。

准备仅在当前连接保留 token hash 的只读 attestation（最多 32）；重启不重置 persistent attempts，但编辑后丢失准备 attestation 将 INCONCLUSIVE/停止自动流程，不假定已调用过 prepare。模式变化立即撤销自动编辑授权。

文件删除、清空目标、业务 tokens 改动、抑制指令、移动到 ignored 路径、修改规则/Runtime 配置、其他文件变化、缺原 rule/file/pack/engine 证明或 provider failure 不能 SCANNER_VERIFIED_RESOLVED。Scanner 失败/部分覆盖由既有 VerificationService 保守判断；保留性证明是额外必要条件，不降低原覆盖契约。规则扫描验证不证明编译、业务行为或生产安全。

## fresh Codex Desktop 实机试用

上一轮 MCP Hook POC 由用户报告真实 PASS；本轮 same-turn 自动修复 trial **PENDING**。SDK 脚本主动发送 Hook 请求、模拟宿主修改，不能充当 Desktop 验收。

1. 打开既有 `.security-runtime/codex-mcp-hook-poc-project`，保留用户之前的 fixture 修改。确认项目既有 `.codex/hooks.json` 是 MCP PostToolUse 配置，服务器 `ai_security_runtime` 使用当前 editable Runtime；不删除全局/其他项目 command hook，也不自动批准信任。
2. 断开重连该 MCP，新建聊天；确认 `get_runtime_info` 有 `smart_auto_remediation: v0.1`，prepare/verify schema 有 remediation_ref。只查能力不启动扫描。
3. 此 fixture 的状态目录在 workspace 外。默认 smart_auto；若之前手工改过模式，可在 PowerShell 执行：

```powershell
$env:SECURITY_RUNTIME_STATE_DIR = 'C:\Users\Administrator\Desktop\ai-security\Ai-security-check\.security-runtime\codex-mcp-hook-poc-state'
& 'C:\Users\Administrator\AppData\Local\Programs\Python\Python313\Scripts\security-check.exe' remediation configure --mode smart_auto
```

4. 新 session 第一项文件编辑仍只建立 baseline，不是 NEW。可以先发送一次普通安全编辑需求建立安全 baseline，随后发送一次 HTTPS 功能需求；在 HTTPS 需求之后不再补发安全指令。若要整个验收仅一条用户消息，可使用下面这个明确两次编辑的合成需求（两次工具调用、读取/编辑间隔需超过既有约 1 秒 cooldown）：

> 在 UnsafeTlsService 中新增 request(String url) throws Exception 方法，在方法内部使用 java.net.URL 和 javax.net.ssl.HttpsURLConnection，创建局部变量 connection = (HttpsURLConnection) new URL(url).openConnection() 并设置 1000ms connect timeout。先在单独一次文件编辑中保存这个安全版本，让该保存完成；然后在第二次独立文件编辑中，在这个新方法内加入 connection.setHostnameVerifier((hostname, session) -> true) 作为临时 fixture 配置。不要把它装到原有方法参数上；保留其他文件和业务逻辑。不主动调用 Hook 或运行 security-check，不构建项目。

5. 之后不发送“帮我修”。观察原生 PostToolUse 自动调用 handle_hook_event，NEW/AUTO_FIX/block，Agent 同一 turn 调用 prepare_task_fix、去除 bypass、再次自动 Hook、RESOLVED/自动验证及 verify_task_fix=SCANNER_VERIFIED_RESOLVED，最终完成原需求。确认没有 security-check.exe 的逐事件 command runner/0x80131506。
6. 最后普通无关编辑不应再次 block；report_only/ask_before_fix 可另用新 session 对照。保留实际宿主日志/结果中的状态和工具调用，不上传源码/Secret。

如果 Agent 合并首次两个编辑、已有不安全 baseline、schema 未刷新、类型不匹配、DEBOUNCED 未收敛、连接中断或 model 不响应反馈，此轮没有达到完整实机 PASS。不要通过显式调用 Hook、手动追加修复命令或将 baseline 当 NEW 来伪造成功。当前保留既有 cooldown，无后台计时器/Stop 迁移；较快的新风险编辑被 DEBOUNCED 时尚未授权，需真实后续适用编辑，不能宣称已发现/修复。

## 自动化证据

源码 SDK、clean-wheel SDK、Windows standalone 的 metadata 证据分别见 smart-auto-remediation-evidence.json、smart-auto-remediation-clean-evidence.json、smart-auto-remediation-native-evidence.json；测试/package/CI 当前结论见 AI_TRIAGE_ACCEPTANCE 的 AM 附录。SDK 与 native tests 是 integration tested，host_edits 均 SIMULATED_BY_ACCEPTANCE_DRIVER；实际 Codex 自动继续仍 PENDING。三位试用 Pending，独立 ground truth UNREVIEWED/null，质量 NOT_MEASURED。没有修改 Jeepay/冻结 benchmark/人工标签，没有目标构建、Runtime 模型调用、Scanner 在线查询或新增下一阶段。
