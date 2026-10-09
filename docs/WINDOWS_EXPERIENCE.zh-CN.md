# Windows 本地安全核查体验（R2.2）

[English](WINDOWS_EXPERIENCE.md) | 简体中文

这是 v0.3.1 的本地体验构建，未发布 Release。保留 ZIP 中整个 `security-check`
文件夹，无需开发机 Python。首次引擎和漏洞数据库准备需要联网。
`version.json` 给出源码提交和未提交修改标志；用
`Get-FileHash <ZIP> -Algorithm SHA256` 核对旁边 `.sha256`。许可证、NOTICE 和
source offer 随包保留。解压到固定位置；以后移动安装目录需要重新 repair。

## 安装与升级

在解压文件夹打开 PowerShell：

```powershell
.\security-check.exe --version
.\security-check.exe runtime-info --json
.\security-check.exe status
```

新安装运行 `.\security-check.exe setup --scope global`；已有安装运行
`.\security-check.exe repair`，使 Runtime 指向新包。随后：

```powershell
.\security-check.exe review-skill install
.\security-check.exe review-skill status
```

完全退出并重启 Codex Desktop，在新聊天确认 Runtime MCP 连接及 AI Security
Review Skill 可见。按宿主提示审核信任 Hook，Runtime 不替你批准。可以选该
Skill，也可直接说“核查当前项目的安全风险”；无需输入 Finding ID。

Skill 默认装到用户 `.agents/skills/ai-security-review`。`review-skill` 的
`upgrade`、`repair`、`remove` 和 `status` 管理同一安装。用户修改托管文件时
返回 USER_MODIFIED 并保留；自定义附加文件、其他 Skill 均保留。Skill 移除
独立于 Runtime `uninstall`。宿主禁用设置需用户恢复，安装器不改变它。

## 六步体验清单

1. **创建隔离项目。** 在 PowerShell 建唯一临时 Git 仓库，然后在 Desktop 打开：

   ```powershell
   $reviewDemo = Join-Path $env:TEMP ('security-review-' + [guid]::NewGuid())
   New-Item -ItemType Directory -Path $reviewDemo -ErrorAction Stop | Out-Null
   git init $reviewDemo
   New-Item -ItemType Directory -Path (Join-Path $reviewDemo '.codex') | Out-Null
   [IO.File]::WriteAllText((Join-Path $reviewDemo '.codex/config.toml'), "[features]`nhooks = false", [Text.UTF8Encoding]::new($false))
   ```

   确认此演示项目的 Hook 已关闭、MCP 仍连接。不要改正常业务项目，不执行网络样例。
2. **无 Hook 扫描。** 说：“只在此临时项目创建 Java 安全核查样例，使用信任所有
   主机名的 HttpsURLConnection verifier 并安装到 connection。不执行代码。
   扫描这个项目，显示实际覆盖和风险。”记录 scanner 执行及 FULL/PARTIAL 原因。
   FULL 不是项目安全声明。
3. **核查与续办。** 说：“使用 AI Security Review 核查第一个风险，分批处理，不
   修改代码”，再说“继续这个任务”。观察脱敏证据、需处理风险和待确认项。
   样例位置不能证明误报；旧扫描没有版本证明时只能给当前上下文。
   断开重连后继续应复用有效评审、重新准备 session，不要求用户输入 UUID。
4. **授权修复并验证。** 说：“修复刚才这个任务，并用原扫描器和规则验证。”
   观察原任务保持一致、代码实际修改与 scanner 重检。只有
   SCANNER_VERIFIED_RESOLVED 表示此规则范围内解决；INCONCLUSIVE 要说明原因。
   代码变化须刷新相关结论，验证不代表业务／部署正确。
5. **亲自验证 Hook 自动反馈。** 仅将演示项目配置改为 `hooks = true`，完全重启
   Desktop，审核当前 Runtime Hook 并确认启用。说：“仅为隔离演示，把 verifier
   临时改回恒为 true 并安装，不运行网络代码。”观察编辑后自动出现安全反馈。
   当前 remediation 模式决定建议／确认／修复；需只看建议时，先记录
   `remediation status`，自行选择 `remediation configure --mode report_only`，
   体验后恢复原模式。未触发／未信任／不可见均记录失败，不以手动扫描代替。
6. **收尾与记录。** 明确要求修复演示风险并验证，记录覆盖、Finding、未知项、
   原规则验证和 Hook 反馈。保留现场以便复盘，不自动抑制或宣布安全。
   无需发布代码、tag 或 Release；关闭演示项目，再决定下一阶段。

## 已知限制与验收

Runtime 不内置 LLM 核查调用，宿主分析证据。脱敏可能隐藏所需语义，未知项必须
保留。工作区／链接／大小／编码／版本检查失败会给明确原因。原始 Finding、
人工质量评审、AI triage、扫描覆盖和修复验证分别报告。行移动可能改变 quality
finding_id，未实现自动语义关联。宿主可能把脱敏上下文发送给所选模型。

自动 stdio 和隔离脚本只证明工具路径。本轮新包的自然语言选 Skill、无 Hook
桌面核查和 Hook 自动提示可见性，需要你亲自完成六步，记录 PASS/FAIL/未验证及
原因。此前 Desktop 结论不自动继承。官方约定：
[Skills](https://learn.chatgpt.com/docs/build-skills)、[Hooks](https://learn.chatgpt.com/docs/hooks)。
