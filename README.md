# AI Security Runtime

在 AI 编程聊天中检查本次开发改动，结合静态检查与 Agent 对关联代码的分析，说明风险依据、当前防护和未知范围。你决定 **修复** 或 **暂不处理**；Agent 修改代码，Runtime 复查原问题并记录逐项结果。

当前为 **Developer Alpha 试用版**，主要试用宿主是 Codex。源码在本机检查，首次准备扫描组件和漏洞数据需要联网。完整安装包自带 Python，**无需安装 Python、pip 或 venv**，也不会安装你的项目依赖或启动项目服务。

本分支新版 Skill 的开发任务核查仅支持 **v3**，须配套具备 v3 能力的 Runtime；下列现有发布包不会自动包含本分支改动。[升级影响与历史任务处理](docs/TASK_REVIEW_V3_ONLY.zh-CN.md)。

## 安装到 Codex：三步

### 1. 下载并解压完整包

当前发布版为 [v0.3.4](https://github.com/pikachu-cxy/Ai-security-check/releases/tag/v0.3.4)。按系统下载：

| 系统 | 下载完整包 |
| --- | --- |
| **Windows x64（优先试用）** | [ai-security-runtime-v0.3.4-windows-x64.zip](https://github.com/pikachu-cxy/Ai-security-check/releases/download/v0.3.4/ai-security-runtime-v0.3.4-windows-x64.zip) |
| Mac：Apple Silicon（M1/M2/M3/M4 等） | [ai-security-runtime-v0.3.4-macos-arm64.tar.gz](https://github.com/pikachu-cxy/Ai-security-check/releases/download/v0.3.4/ai-security-runtime-v0.3.4-macos-arm64.tar.gz) |
| Mac：Intel | [ai-security-runtime-v0.3.4-macos-x64.tar.gz](https://github.com/pikachu-cxy/Ai-security-check/releases/download/v0.3.4/ai-security-runtime-v0.3.4-macos-x64.tar.gz) |

解压到一个新文件夹，保留完整的 `security-check` 子目录；不要下载 GitHub 的 **Source code** 包或只复制可执行文件。[SHA256 校验方法见下方](#下载校验与详细操作)。Mac 不确定芯片型号时查看“关于本机”。Linux 暂不发行。

### 2. 退出 Codex，执行两条命令

在**包含 `security-check` 子目录的解压文件夹**中打开普通 PowerShell，逐条执行；任何一步失败就停止，按[详细指南](docs/PILOT_INSTALL_AND_USE.zh-CN.md#升级重试和卸载)处理。

```powershell
.\security-check\security-check.exe install codex
.\security-check\security-check.exe preparation watch
```

第一条安装 MCP、Codex 生命周期 Hook 和配套 Skill，并自动在后台准备检查组件；第二条等待准备结果。看到 **“扫描能力已准备完成”** 再继续，下载中或失败都不表示检查已就绪。

<details>
<summary>Mac：解压后使用这两条命令</summary>

完全退出 Codex，在包含 `security-check` 子目录的解压文件夹打开终端，逐条执行：

```bash
./security-check/security-check install codex
./security-check/security-check preparation watch
```

Apple Silicon 与 Intel 使用相同命令，下载包按上表选择。若系统阻止运行，保存提示并参考[Mac 详细步骤](docs/PILOT_INSTALL_AND_USE.zh-CN.md#macoscodex自动接入真机待验)；当前没有 Apple 开发者签名／公证承诺，不要关闭系统安全检查。macOS CI 与试用者真机验收分别记录，维护者暂无 Mac 真机，平台限制见[开发进度](docs/DEVELOPMENT_PROGRESS.md)。

</details>

### 3. 重启 Codex，确认接入

完全重新打开 Codex，在实际项目目录创建新聊天，先发：

> 请只核对已连接的 ai_security_runtime 的版本和构建身份，不扫描、不修改代码。

确认 MCP 已连接，返回版本为 **0.3.4**，构建身份与解压包的 `security-check/version.json` 一致。连接成功只代表已接入；发一个普通开发需求后，最终回复应说明实际安全核查结果或未完成的范围，不能把“工具已列出”当作检查已运行。

之后正常提开发需求，无需额外说“使用 ai-security 扫描”，也不要求 `git commit`。有风险时，查看依据、防护、触发条件和未知范围，再选择 **修复／暂不处理**。多个问题要指明具体项；批量修复需明确说“修复本轮全部已登记风险”。暂不处理保留记录，修复后逐项区分复查通过、仍存在和验证未完成。

Git 提交 Hook **默认关闭、常规帮助隐藏**；默认安装保留已有 Git Hook。

## Cursor 接入测试版

本分支源码新增 Cursor 全局 MCP、自动 Hook、公共 Skill 和常规检查工具免确认配置。
已发布的 v0.3.4 安装包不因此自动包含这些新改动；请使用包含 Cursor 连接器的新构建。
在完整候选包中运行 `security-check.exe install cursor`，再重启 Cursor。
安装器只预批准本产品指定的检查和记录工具，保留原有权限设置，修复仍需明确同意。
Cursor 运行模式、团队策略和模型额度仍独立适用。

安装、升级及验收范围见 [Cursor 安装指南](docs/guides/CURSOR_INSTALL_AND_TEST.zh-CN.md)。

## 下载校验与详细操作

<details>
<summary>校验下载包（安装前）、升级、卸载、离线和故障排查</summary>

安装前下载 [v0.3.4 SHA256SUMS.txt](https://github.com/pikachu-cxy/Ai-security-check/releases/download/v0.3.4/SHA256SUMS.txt)，在下载目录计算对应压缩包的 SHA256，与清单中同名文件核对：

```powershell
Get-FileHash -Algorithm SHA256 -LiteralPath .\ai-security-runtime-v0.3.4-windows-x64.zip
```

Mac 使用 `shasum -a 256 ai-security-runtime-v0.3.4-macos-arm64.tar.gz`，Intel 将文件名中的 `macos-arm64` 换为 `macos-x64`。不一致时不要安装。

- [详细安装、准备状态、重试、升级和卸载](docs/PILOT_INSTALL_AND_USE.zh-CN.md)：需要诊断时核对组件整体 `ready=true` 与漏洞库 `FRESH`；仍在下载时依赖检查未完成。升级使用新 Release 的完整包重复安装，再重启核对构建身份。
- [离线安装、缓存与本地差分包](docs/guides/PERSONAL_INSTALL_AND_GUIDANCE.zh-CN.md#安装缓存与增量升级)：离线只复用已有可用缓存，不能从零准备缺失组件。当前没有在线产品自动下载更新器，也没有漏洞库持续定时刷新服务。
- [Hook 诊断与使用反馈](docs/PILOT_INSTALL_AND_USE.zh-CN.md#接入与自动检查诊断)：确认项目、时间和执行状态；没有记录不能直接断言没有触发。

卸载接入和 Skill 保留程序数据与检查历史。遇到未知配置冲突时保留诊断，按详细指南处理，不手动删除其它服务。

</details>

<details>
<summary>其它客户端／仅 MCP 接入（按需）</summary>

如只需主动调用工具，或客户端使用本地 stdio MCP，请看[仅 MCP 模式](docs/PILOT_INSTALL_AND_USE.zh-CN.md#仅mcp模式windowsmacos)：跳过 `install codex`，准备组件后生成项目配置，合并进客户端并重连。此模式不安装 Hook 或 Skill；普通浏览器远程聊天不能直接启动本机程序，自动调用取决于客户端行为。本批主要验收 Codex，其它客户端不承诺相同自动核查体验。

</details>

反馈到 [Issues](https://github.com/pikachu-cxy/Ai-security-check/issues)：提供系统／架构、版本和构建身份、失败步骤及准备状态。分享前去除私有代码、真实密钥和个人路径。

## 检查范围与开发资料

支持 Java、Python、JavaScript／TypeScript 的已安装规则子集、密钥检测、可识别依赖版本和有界关联代码分析。没有发现问题不证明项目安全；未支持输入、缺失组件、上下文预算和未知部署条件须保留。声明版本的原公告复查通过，不代表完整依赖图或实际部署安全。

- [详细安装使用指南](docs/PILOT_INSTALL_AND_USE.zh-CN.md)
- [开发进度与限制](docs/DEVELOPMENT_PROGRESS.md)、[下一步计划](docs/NEXT_DEVELOPMENT_PLAN.zh-CN.md)
- [规则范围](docs/design/RULE_FOUNDATION.md)、[覆盖矩阵](docs/design/RULE_COVERAGE_MATRIX.md)
- [开发交接](docs/DEVELOPMENT_HANDOFF.zh-CN.md)
- [许可说明](LICENSING.md)、[使用条款](EULA.md)、[第三方声明](THIRD_PARTY_NOTICES.md)

安装入口为 Releases 完整包，Homebrew／winget 外部上架不作为试用安装前提。

## 架构统一进度（源码 0.3.6）

Codex 与 Cursor 共用同一业务核心、任务编排、扫描执行及风险处置；连接器保留事件时机、传输和呈现差异。本轮补齐持久事件与交付记录、逐写路径恢复、固定扫描输入与短锁、按需 Skill 方法和包级存储兼容门槛。近期原生修复意图、影响未知分级、会话归属、真实基线与累计额度继续保留。[当前架构图、流程和验收](docs/ARCHITECTURE_UNIFICATION_COMPLETION.zh-CN.md)。

开发核查只使用 **v3**。新版 Skill 要求同一 Runtime 构建具备 v3 与九项任务工具；旧协议任务仅保留只读历史，不自动迁移或改后补基线。升级清理未被用户修改的旧受管方法，保护用户自定义内容。新账本启用后，缺少对应存储能力的旧二进制不能安全回退。[升级说明](docs/TASK_REVIEW_V3_ONLY.zh-CN.md) · [事务与恢复](docs/PERSISTENCE_TRANSACTION_RECOVERY.zh-CN.md)。

本轮全量回归完成：4978 项通过、17 项跳过、26 项预期失败，零失败与错误；四片无重复用例、无源码漂移。wheel 的正式隔离安装验证通过，独立 Windows 候选正在构建验收；原诊断失败回执保留。历史索引与输入捕获的[实测成本](docs/ARCHITECTURE_PERFORMANCE.zh-CN.md)单列，不把模拟事件当作真实用户体验。双宿主桌面实测依用户决定暂缓；源码、候选构建、当前安装与公开 Release 分别认定，GitHub 同步不会自动更新现有安装。

旧任务更新被拒的原因已确认：旧 Runtime 账本总量超限；另一次资源占用来自锁超时。保留原任务和证据，不清空历史或重建基线。当前最终任务核查状态见[诊断与限制](docs/ARCHITECTURE_REVIEW_DIAGNOSIS.zh-CN.md)，代码回归不替代安全核查。

## 项目文档

- [文档导航](docs/README.md)：当前状态、使用指南、设计与历史记录。
- [开发进度](docs/DEVELOPMENT_PROGRESS.md)与[近期计划](docs/NEXT_DEVELOPMENT_PLAN.zh-CN.md)。
- [Cursor、Qoder、WorkBuddy / CodeBuddy 接入](docs/HOST_SUPPORT.md)。
- [个人版与企业版规划](docs/PRODUCT_ROADMAP.md)、[功能验证的企业研发项](docs/FUNCTIONAL_VERIFICATION.md)。

当前源码中的功能验证默认入口已隐藏；公开下载、隔离候选和当前安装分别记录。

## 较早修复影响候选记录（2026-10-18）

下文保留架构升级前 **2026-10-18 / 0.3.6** 修复影响阶段的候选与失败事实；当前架构验收以上一节为准。当时写入的修正包括：

- 先说明具体修复方案对正常业务的影响，再沿用用户对选定问题已有的修复请求；只问影响时不编辑代码，也不重复要求通用批准。
- 代码复核发现的风险有独立修复准备入口，关联原风险、影响评估和编辑前记录；准备未完成时保留等待状态，防止另建普通任务替换修复起点。
- 工具参数明确声明来源、影响类型、覆盖状态、业务选择及分页范围；参数错误返回有界的字段提示、合法值和修正建议，不回显提交的源码或凭据。
- 用户可明确暂停选定修复或改做其他工作；暂停流程保留原风险和历史。风险的“稍后处理／不再提醒”分别保存，恢复提醒不等于授权修复。

过宽的“不运行构建测试”提示已在源码收窄：用户明确要求或原开发任务包含的测试、构建与验收照常执行，无需重复确认；仍禁止伪造检查结果、重放事件或补建编辑后基线。构建脚本纳入本轮回归范围、六个必要工具和实际包内参数契约门禁。**本轮已开始回归；实际失败及后续验证、构建和安装分别以本轮真实回执判定**，具体结果见[开发进度](docs/DEVELOPMENT_PROGRESS.md)，不能从源码修改推定已通过或已生成新包。

旧本地候选 **0.3.6 / `d6ac9d9e0eb3842571f5acac713e057701672b459f3ec1df65908aa72bd4d2b5`** 不包含本轮优化。其记录曾保存 **69 项影响相关用例、1064 项去重回归通过**，只适用于当时的冻结输入，不能作为当前源码已通过的证据；旧候选上的 **A/B/C 桌面验收均未整体通过**。使用 `artifacts/repair-impact-latest.json` 时必须核对批次、源码摘要和 build_id，不能仅凭文件名中的 latest 认定已生成新版。

上方公开下载链接仍指向已发布包。后续需先完成当前源码验证并生成新候选，再安装、完全重启宿主，核对实际构建身份后验收。旧 A 可查历史及当前权限代码；旧 B 可在原聊天核对后续办；旧 C 可直接查暂缓历史，只有重新准备评估时才由用户明确恢复提醒，恢复提醒仍不等于授权修复。完整流程更适合使用不覆盖旧目录的 A2/B2/C2 新起点，见 [修复影响安装与验收](docs/REPAIR_IMPACT_ACCEPTANCE.zh-CN.md)。

自适应额度、信息去重、续接和大改动覆盖见 [自适应复核验收](docs/ADAPTIVE_REVIEW_ACCEPTANCE.zh-CN.md)。后续候选归档仍采用 `ai-security-runtime-v0.3.6-windows-x64.zip`、`ai-security-runtime-v0.3.6-macos-arm64.tar.gz`、`ai-security-runtime-v0.3.6-macos-x64.tar.gz` 命名；名称不代表已公开发布或已通过 Mac 真机验收。
