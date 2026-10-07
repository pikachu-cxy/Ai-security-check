# P0-9.5 — First-Scan Mutation Attribution

## 状态与范围

共享 Runtime 的归因实现与最终 focused/full 离线回归已完成。真实 managed Scanner 的归因 assertions 已通过，实际 Cursor command policy integration 为 PARTIAL：现有只读 AdvisoryTransportConfig 缺少 path，既有 RemediationService 返回 REMEDIATION_INCONCLUSIVE。用户已明确要求保持冻结、记录独立阻塞、后续再修。不能将泛化 ADVISE 等同于成功的 Remediation Offered。

本轮未执行真实 Desktop E2E，不安装活动 Runtime，不修改真实 .cursor/.codex，不 commit/push。Cursor continuation 仍 PENDING_CURSOR_CONTINUATION_CAPABILITY。P0-9.4 transport/binding/lifecycle 的真实 Desktop 通过来自用户反馈，不是本轮执行。

## 根因

SessionStart 已正确发布 filesystem-only COMPARISON_BASELINE，只有 workspace/session 绑定及每文件 keyed digest，没有安全 Finding baseline。此前首次扫描即使确认 digest delta、发现 TLS 风险，也不能从“空 family inventory”推出 pre-edit 无风险。因此保守返回 FIRST_SCAN_UNATTRIBUTED_RISK_PRESENT。

现有 snapshot 也不包含旧源码字节，不能从 HMAC 反推原文件。新增代码不把 Git clean/index 状态当安全依据；只用 Git 作为旧字节恢复来源。

## 证明链

1. 保留 SESSION_BASELINE，SessionStart scanner=false。
2. 原 filesystem reconciliation 确认 current digest delta，并执行原 managed quick scope scan。
3. 仅在 COMPARISON_BASELINE + 当前 risk 时尝试 targeted attribution。
4. 从已有 Git index/HEAD 解析固定 blob OID，检查 size 后读取。恢复字节必须与当前 workspace key 下可信 pre-edit file HMAC **完全一致**。LF→CRLF 只作为 recovery candidate，只有 exact HMAC 命中才使用；不归一化 scanned source，不修改 BOM。
5. 将当前风险所在 changed files 的旧字节 materialize 到一次性临时树；保留 relative identity，不复制整个 repo/manifests，不改原文件。
6. 复用同一默认 managed SemgrepAdapter、选中 rule/config、版本、FindingNormalizer 与原 covered()。启动前已有 ToolManager content-validation identity 经临时 ContextVar 收集；执行前后核对引擎、rule pack checksum/rule versions/config identity。不是仅比较 version 字符串。
7. 对 source before/after digest 和最终 workspace snapshot 再核对。真实 pre scan 覆盖完整、风险 identity 可匹配才交给原 family_delta；成功后提交原 HookSnapshot。

默认 bundled Semgrep 路径支持等价证明；unsupported provider/plugin 或混合风险不伪造 absence proof。当前风险仍来自原 Finding DB；pre-edit scan 不创建第二套 Finding/DB，不持久化源码、scanner identity 或 Git blob。

## 旧风险和新实例

同 family/rule/file identity 匹配旧、新 Scanner findings。旧 occurrence 的 exact unchanged source span 经行移动映射到当前位置，做 one-to-one consumption。已有 TLS 风险 + timeout edit 保持 existing；同 rule 第二处风险产生 newly_attributed_risk_count=1、additional_occurrences=1，原 family 为 PERSISTING，不伪造第二个 NEW family。

旧风险 span 被改写、位置匹配含糊、风险已删除又发生其他风险时，不能可靠映射就 inconclusive。仅靠 count/file presence 不授权 new attribution。原 policy 对多个候选的授权限制未调整。

## 安全失败边界和能力限制

缺 snapshot、旧字节未存于现有 Git index/HEAD、dirty old content 不匹配、non-Git/untracked old content、target identity 不一致、provider/version/engine/rule/config mismatch、scanner failure/incomplete coverage、moving source、预算超限：不产生 NEW、不推进可信 comparison snapshot，不清除待处理 mutation。保留 FIRST_SCAN_UNATTRIBUTED_RISK_PRESENT；当前真实 scan candidates 仍可审阅。

新增 Git blob recovery 超时转换为 NO_TRUSTED_PRE_EDIT_BYTES / FIRST_SCAN_ATTRIBUTION_INCONCLUSIVE；不会将读取失败解释为安全。严格 HMAC/containment/session/coverage 校验没有放宽。

范围上限：16 个 risk-bearing changed targets，1 MB/file，before+after 合计 4 MB；line mapping 总计 10,000 行及 4M 比较预算；沿用既有 Git/Scanner process timeout。没有宣称新的全流程 wall-clock deadline。

**当前并不能保证所有可信 digest snapshot 都能恢复旧字节。** 本轮不新增源文件 vault，也不改变 SessionStart。不可恢复时继续 unknown 是实际能力边界，不能用“HEAD 中无风险”替代 pre-edit proof。

## Diagnostics

新增 closed enum/bool/count/duration：first_scan_attribution_attempted、pre_edit_targeted_scan_run/count、first_scan_attribution_status/reason、pre_existing_risk_count、newly_attributed_risk_count、attribution_scanner_equivalent、first_scan_attribution_ms。经既有 cross-process bounded SQLite recent 保存；不是授权或 proof store。

scanner_invocation_count 保持 Core scanner dispatch count：风险首次归因 fixture 为 current+pre=2，安全 edit 为1，SessionStart/Stop 为0；不是 version probe/OS process 总数。first_scan_attribution_ms 测量 pre helper 的真实 monotonic wall interval，不含 current scan 后最初的 detector stamp capture，因此不能当全部额外成本；hook duration 是完整窗口。

不保存 raw source、snapshot bytes、Git blob、Secret、原始 command/tool input/output/transcript、raw session/generation/ref/token。无新模型、build、Full Scan、Deep Verification 调用。

## 实现文件

- src/security_runtime/first_scan_attribution.py：byte recovery、真实 targeted pre scan、equivalence、occurrence matching、诊断。
- src/security_runtime/hook_runtime.py：原共享协调器接入；失败时保留 comparison point/pending。
- src/security_runtime/toolchain.py：收集已有 startup probe identity，两行 instrumentation；不改变缓存/执行语义。
- src/security_runtime/recent_hooks.py：安全 diagnostics allowlist。
- src/security_runtime/codex_mcp_hook.py：兼容性 compact result 投影。
- tests/test_first_scan_attribution.py：25 个新增 cases。
- tests/test_cursor_event_lifecycle.py：fake detector 不可证明等价时，保持 COMPARISON_BASELINE 的断言。
- MANIFEST.in：新增测试进入 sdist。
- 既有五份状态/架构/决策/阶段/验收文档及本轮 JSON：真实状态，不改历史。

Cursor Adapter/workspace anchor/lifecycle/generation/HostEvent contract、Scanner/规则、Finding/Policy、Family/Episode、remediation、Ticket、Exact Edit Envelope、Deep implementation 均逐字节或原 schema AST 核对保留，见 workspace audit。

## 验收记录

最终 focused：164 passed in 189.62s (0:03:09)。
最终 full offline regression：1712 passed, 9 skipped, 6 subtests passed in 2095.23s (0:34:55)。skipped 单列，不计 PASS：

- SKIPPED [1] tests\performance\test_managed_cache_lifetime.py:14: Explicit managed real Scanner benchmark environment required
- SKIPPED [1] tests\performance\test_managed_cache_lifetime.py:38: Explicit managed real Scanner benchmark environment required
- SKIPPED [1] tests\performance\test_managed_hot_path.py:10: Explicit managed real Scanner benchmark environment required
- SKIPPED [1] tests\test_e2e_real.py:58: real scanner binaries required
- SKIPPED [1] tests\test_e2e_real.py:80: real scanner binaries required
- SKIPPED [1] tests\test_e2e_real.py:120: real scanner binaries required
- SKIPPED [1] tests\test_e2e_real.py:154: real scanner binaries required
- SKIPPED [1] tests\test_e2e_real.py:68: real scanner binaries required
- SKIPPED [1] tests\test_e2e_real.py:38: real scanner binaries required

早期定向曾 5 failed / 14 passed：修正 pending completion 与既有 policy 断言后通过。中间版 expanded focused 451 passed，执行 identity 补强后 focused 163 passed；最终补齐旧 blob timeout 后重新跑 focused/full。旧版未完成的 full 已停止，不计通过。
当前源码 managed Scanner / 独立 Cursor command trial：attribution assertions PASS；整体 PARTIAL / BLOCKED_PRE_EXISTING_CURSOR_POLICY_CONFIG_PATH，62.08s。跨进程 recent 查询、临时目录清理通过。
真实 Codex MCP stdio + managed Scanner simulated Host：PASS / 59.59s；两轮 Episode 均 INLINE_PREPARED → Envelope MATCHED → SCANNER_VERIFIED_RESOLVED / CLOSED，原 opaque refs 逐字一致；未运行 Desktop。
wheel/sdist/package integrity/compliance PASS，89 个模块逐字节一致；最终候选 wheel 的隔离 candidate venv 安装 PASS / 5.41s。依赖来自既有 system-site-packages，--no-index --no-deps，无下载，未宣称依赖完全隔离。

### 实际耗时与 scope

串行单样本、独立冷 command processes、既有 managed engines；BEFORE 为任务开始时保存的 P0-9.4 未提交工作区，不是当前 Git HEAD。不是 Desktop 基线，也不能从一个样本宣称统计性能改善。

| 版本 / 场景 | Hook duration ms | Scanner ms | pre helper ms | Core scan dispatch |
|---|---:|---:|---:|---:|
| BEFORE / SAFE_EDIT | 6097 | 5600.14 | None | 1 |
| BEFORE / NEW_TLS | 6038 | 5550.935 | None | 1 |
| AFTER / SAFE_EDIT | 5920 | 5434.449 | None | 1 |
| AFTER / NEW_TLS | 14827 | 5757.924 | 7760.295 | 2 |

所有 SAST scope 为1个 Java file / 21 rules / repository_discovery=false；Semgrep 1.178.0 / Gitleaks 8.30.0。safe edit 不增加 pre scan；首次风险新增1次真实 targeted Semgrep，增加真实 proof 成本，未取消安全动作。pre helper 不是全部额外成本，不能与其他窗口随意相加。
独立 Cursor trial 中 NEW_TLS=NEW；EXISTING_TLS=existing；EXISTING_PLUS_NEW=existing1/new1、additional_occurrences1；safe edit=FIRST_SCAN_NO_RISK。SessionStart/Stop dispatch均0。每个 real command 的政策结果仍明确 REMEDIATION_INCONCLUSIVE，因此归因成功不等于 Cursor policy offer 完成。

证据：[regression](first-scan-attribution-regression.json)、[managed Cursor trial](first-scan-attribution-real-trial.json)、[serial performance](first-scan-attribution-performance.json)、[Codex MCP](first-scan-attribution-codex-trial.json)、[package](first-scan-attribution-package.json)、[candidate install](first-scan-attribution-clean-install.json)、[workspace audit](first-scan-attribution-workspace-audit.json)。

## 下一次用户 Desktop 最小试验

本轮不会安装、升级或代跑。用户后续自行使用候选版本，在 Project F 选择已受 Git 跟踪、当前安全、旧字节可从已有 index/HEAD 恢复的 TLS 文件；不要通过 Runtime 创建新的安全 baseline scan。新建 Cursor conversation，确认 sessionStart = SESSION_BASELINE / PUBLISHED / scanner=false；然后仅让 Agent 加入一行 hostname verifier bypass，不主动安全扫描、build/test。

独立 PowerShell 查询：

```powershell
security-check hooks recent --path "C:\Users\Administrator\Desktop\ai-security\runtime-cursor-e2e-f" --limit 8 --json
```

期望 afterFileEdit claims/binding VALID、digest delta=true、current scanner=true、FIRST_SCAN_NEW_RISK_ATTRIBUTED、pre_edit_targeted_scan_count=1、pre_existing_risk_count=0、newly_attributed_risk_count=1、attribution_scanner_equivalent=true。SessionStart/Stop 仍 scanner=false。

如果旧 bytes 不可恢复，应看到明确 attribution reason 和 inconclusive，不得伪造 NEW。当前冻结的 Cursor config.path 错误可能仍返回 REMEDIATION_INCONCLUSIVE；这与 attribution diagnostics 区分记录，不能声称本轮完整 policy offer 已验证。Cursor 自动 Agent fix/CLOSED 仍不在能力承诺内。
