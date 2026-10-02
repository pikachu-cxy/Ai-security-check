# AI Security Runtime

默认 `ai-security-core 1.1.0` 包含 22 条 BETA Java 规则和两条 Python 规则。
Rule Coverage 参与执行计划：零适用规则显示 `NOT_COVERED`，不准备、不启动 Semgrep；
Java 已执行而 JavaScript 无规则时，`CODE_SAST=PARTIAL`。
详见 [实际规则覆盖](docs/RULE_COVERAGE.md)，包括完整 catalog、质量门禁及覆盖边界。

扫描超过 500 ms 时，CLI 会在 **stderr** 显示实际的项目发现、引擎准备、
下载、数据库准备和扫描状态；最终结果及 JSON 仍输出到 **stdout**。
交互终端每秒更新实际耗时，重定向日志每 10 秒提供一次 heartbeat，
短任务保持安静，不预测百分比。只显示本次计划中的引擎。

脚本可使用 `security-check scan --mode release --json --no-progress` 关闭进度，
真正的 CLI 错误仍写入 stderr。`--verbose` 会额外显示本次不适用的能力。
扫描 human 结果统一为中文，JSON 枚举保持英文。Ctrl+C 会取消扫描并停止
外部引擎及其子进程；library 和 MCP 默认不会开启 CLI 进度。
失败后的简短重试命令应在原项目目录运行。

[English](README.md) | **简体中文**

> **Agent writes. Security Runtime verifies.**  
> AI 负责编写，Security Runtime 负责验证。

AI Security Runtime 是一个面向 AI Coding 工作流的本地优先安全运行时。它可以检查 AI 编程 Agent 生成或修改的代码，并通过 **CLI** 和 **MCP** 向开发者与 AI Coding 工具提供统一的安全能力。

- **本地优先**：项目源码默认保留在本机。
- **一条命令接入**：原生支持 **Cursor** 和 **WorkBuddy**。
- **通用 MCP**：Codex 等其他支持 MCP 的 AI Coding 工具也可以接入。
- **CLI**：不依赖任何 AI Coding 工具，可独立使用，也适合后续接入 CI/CD。
- **不虚报安全**：如果部分扫描能力不可用，会降低 Coverage，而不是把项目误判为安全。

> 当前为 Developer Alpha。SAFE 仅表示已执行检查在所述范围内未发现阻断项，不代表项目绝对安全。

---

## 安装

Package-manager installation is being prepared for the next Developer Alpha release.
GitHub 发行资产、Homebrew Tap 和 WinGet 清单尚未发布，以下命令目前不可用。

### Windows

```powershell
winget install --id PikachuCXY.AISecurityRuntime -e
```

### macOS / Linux x64

```bash
brew install pikachu-cxy/tap/ai-security-runtime
```

Standalone Runtime 自带运行环境。第一次扫描会按需准备独立的 Semgrep、
Gitleaks、Trivy 和数据库，不要求用户安装 Python、pip 或 venv。
项目扫描仍使用 Git，请进入自己的 Git 项目后执行：

```text
security-check --version
security-check doctor
security-check scan --mode quick
```

### 第 3 步：进入你的项目开始使用

例如你的项目在：

```text
C:\Users\你的名字\Desktop\my-project
```

就在 PowerShell 中执行：

```powershell
cd "C:\Users\你的名字\Desktop\my-project"
security-check doctor
security-check scan --mode quick
```

第一次扫描可能会自动准备 Gitleaks、Trivy 等安全工具。

你不需要自己下载安装这些 Scanner。

如果你使用 Cursor：

```powershell
security-check setup cursor
```

如果你使用 WorkBuddy：

```powershell
security-check setup workbuddy
```

就这么开始。

---

### 我只想先试一下，不想扫描自己的项目

仓库已经自带一个故意包含漏洞的测试项目。

在 `Ai-security-check` 目录下执行：

```powershell
cd samples\vulnerable-python
git init
security-check doctor
security-check scan --mode quick
```

如果能看到安全 Finding，说明 Runtime 已经正常工作。

---

<details>
<summary><strong>开发者：使用虚拟环境安装（可选）</strong></summary>

如果你熟悉 Python，并希望把依赖隔离在单独的虚拟环境里，可以使用：

```powershell
git clone -b feature/runtime-mvp https://github.com/pikachu-cxy/Ai-security-check.git
cd Ai-security-check

python -m venv .venv
.\.venv\Scripts\Activate.ps1

python -m pip install --upgrade pip
python -m pip install -e ".[mcp]"
```

普通试用用户不需要使用这一节。

</details>

---

## 2. 第一次使用 CLI 扫描

请在一个 **Git 项目目录** 中运行 AI Security Runtime。

为了方便安全验收，可以先复制仓库自带的故意包含漏洞的示例项目，创建一个临时 Git 仓库。

### Windows PowerShell

在 `Ai-security-check` 目录下执行：

```powershell
New-Item -ItemType Directory -Force ..\security-runtime-demo | Out-Null
Copy-Item -Recurse .\samples\vulnerable-python\* ..\security-runtime-demo\
cd ..\security-runtime-demo
git init
```

先检查运行环境：

```bash
security-check doctor
```

然后执行扫描：

```bash
security-check scan --mode quick
```

扫描只准备本次计划选中的工具。quick 无变更时不下载任何引擎；quick 不准备 Trivy 或漏洞数据库。下载内容在执行前校验，不需要修改系统 PATH。

一次正常的测试应该能够：

1. 正确识别当前 Workspace；
2. 启动当前可用的本地安全引擎；
3. 从故意存在漏洞的示例项目中发现 Finding；
4. 显示 `FULL`、`PARTIAL` 等 Coverage 状态。

如需机器可读结果：

```bash
security-check scan --mode quick --json
```

### 扫描模式

```bash
security-check scan --mode quick
security-check scan --mode feature
security-check scan --mode release
```

- **quick**：扫描当前修改和未跟踪文件，适合开发过程中快速检查。
- **feature**：扫描当前分支相对 main/master 的差异以及本地修改。
- **release**：扫描项目中已跟踪和未跟踪文件，适合更完整的发布前检查。

---

# 接入 AI Coding 工具

AI Security Runtime 当前提供以下 MCP Tools：

- `scan_diff`
- `scan_project`
- `get_findings`
- `generate_fix`
- `verify`

`generate_fix` 只会返回修复任务和建议，不会静默修改源码。

推荐工作流：

```text
AI 修改代码
    ↓
scan_diff
    ↓
发现 Finding
    ↓
AI 修复代码
    ↓
verify
    ↓
RESOLVED
```

---

## Cursor —— 一条命令接入

进入你希望保护的 Git 项目：

```bash
security-check setup cursor
```

预期结果类似：

```text
AI Security Runtime

Workspace
✓ <你的项目>

Connecting Cursor...
✓ Cursor configuration written
✓ Runtime MCP self-test passed
○ Cursor client connection not confirmed yet
Restart Cursor to load the project connection.

Code stays local.
```

Runtime 会管理项目级配置：

```text
.cursor/mcp.json
```

它会保留项目中已有的其他 MCP Server，只维护自己的：

`ai-security-runtime`

如果提示需要重启 Cursor，请重启。

然后在 Cursor 中输入：

> 使用 AI Security Runtime 检查当前 Git diff，告诉我发现了哪些安全问题。如果存在问题，请修复，并在修复后调用 verify 验证。

真正通过验收的标准不是“配置文件生成成功”，而是 Cursor 能完成：

```text
scan_diff → Finding → 修复 → verify → RESOLVED
```

查看接入状态：

```bash
security-check integrations
```

---

## WorkBuddy —— 一条命令接入

进入目标 Git 项目：

```bash
security-check setup workbuddy
```

Runtime 会管理项目级 WorkBuddy MCP 配置，并保留其他已有 MCP Server。

项目路径为 `<项目>/.workbuddy/mcp.json`，与
[WorkBuddy 官方 MCP 指南](https://www.codebuddy.ai/docs/zh/workbuddy/From-Beginner-to-Expert-Guide/Function-Description/MCP-Guide)
一致。但部分桌面版本在 UI 中使用 `%USERPROFILE%/.workbuddy-ai/mcp.json`。
项目配置写入成功不证明当前版本已加载它。若客户端使用全局 UI，请执行
`security-check mcp config --json`，在 UI 中注册生成的项目绑定配置。
每个项目使用独立条目/服务会话，不要跨项目复用固定的 workspace binding。
本轮尚未实现自动全局注册。

`integrations` 分别展示配置路径、配置状态、Runtime 自测和最后真实 MCP 调用。
`NEEDS_RESTART` 只表示配置与自测成功，等待宿主调用；实际调用后才记录
`CONNECTED`。自测流量不会制造连接记录。连接归属来自配置中的 integration 标识，
不是对客户端 UI 的探测。

Runtime 新建的项目配置使用 `.git/info/exclude` 中可逆的独立块；不会改共享
`.gitignore`，也不会隐藏原有的混合用户配置。

如果提示需要重启 WorkBuddy，请重启。

然后在 WorkBuddy 中输入：

> 使用 AI Security Runtime 检查当前 Git diff，并告诉我发现了哪些安全问题。

确认 `scan_diff` 可以正常调用后，再测试：

> 修复刚才发现的问题，然后使用 AI Security Runtime 验证修复结果。

查看状态：

```bash
security-check integrations
```

---

## Codex 和其他支持 MCP 的工具

Codex 当前通过 **Generic MCP** 接入，不提供专属一键安装。

在你想保护的 Git 项目中执行：

```bash
security-check mcp config --toml
```

如果你的 MCP Client 使用 JSON：

```bash
security-check mcp config --json
```

Windows 下可以直接复制生成的 JSON：

```bash
security-check mcp config --copy
```

生成的配置会包含：

- Runtime 的绝对执行路径；
- MCP 启动参数；
- 当前绑定的项目 Workspace；
- Integration 标识。

把生成的配置粘贴到对应 AI Coding 工具的 MCP 设置中，如有需要重启或重新加载客户端，然后让它执行：

> 使用 AI Security Runtime 检查当前 Git diff。

Generic MCP 的通过标准是：

> 客户端真正能看到并调用 Runtime Tools。

仅仅生成配置文本不算接入成功。

### 如果 AI Coding 工具不支持 MCP

只要它能够执行 Shell 命令，就可以使用 CLI：

```bash
security-check scan --mode quick --json
```

---

# 推荐验收清单

建议 Cursor、WorkBuddy、Codex 都使用同一个临时漏洞项目进行验收。

| 验收项 | 通过标准 |
| --- | --- |
| CLI 安装 | `security-check --help` 正常 |
| 环境识别 | `security-check doctor` 正确识别当前项目 |
| CLI 扫描 | `security-check scan --mode quick` 能发现真实 Finding |
| JSON 输出 | `--json` 返回可解析的机器可读结果 |
| Cursor | `security-check setup cursor` 成功，Cursor 能调用 `scan_diff` |
| WorkBuddy | `security-check setup workbuddy` 成功，WorkBuddy 能调用 `scan_diff` |
| Codex / Generic MCP | 生成配置后客户端能真实调用 `scan_diff` |
| 修复闭环 | Finding → Agent 修复 → `verify` → `RESOLVED` |
| Workspace 隔离 | 切换到另一个仓库后不会读取上一个项目的 Finding |
| 重复 Setup | 多次执行 setup 不重复、不破坏 MCP 配置 |
| 离线复用 | 已安装本地 Tool 在禁止下载后仍能继续使用 |
| 部分能力失败 | 单个 Scanner 不可用时其他 Scanner 继续工作，并显示 PARTIAL |

查看详细状态：

```bash
security-check doctor --verbose
security-check integrations --verbose
security-check tools status
```

---

# 常用命令

### 环境检查

```bash
security-check doctor
security-check doctor --json
security-check doctor --verbose
```

### 扫描

```bash
security-check scan --mode quick
security-check scan --mode feature
security-check scan --mode release
security-check scan --mode quick --json
```

### AI Coding 接入

```bash
security-check setup
security-check setup cursor
security-check setup workbuddy

security-check integrations
security-check integrations --verbose
security-check integrations repair
security-check integrations remove cursor
security-check integrations remove workbuddy
```

### Generic MCP

```bash
security-check mcp config
security-check mcp config --json
security-check mcp config --toml
security-check mcp config --copy
```

### 托管安全工具

```bash
security-check tools status
security-check tools install --all
```

### 本地使用统计

```bash
security-check stats
```

### Git pre-commit Hook

```bash
security-check hooks install pre-commit
```

### License / Distribution 检查

```bash
security-check licenses
security-check licenses --check-distribution
```

---

# 本地到底运行了什么？

当前内置安全能力主要由以下 Engine 提供：

- **Semgrep**：使用本地 first-party `ai-security-core` 规则包进行代码安全匹配。
- **Gitleaks**：Secret 检测。
- **Trivy**：分别执行依赖漏洞（`vuln`）和 IaC（`misconfig`）检查。
- **OSV-Scanner 2.6.0**：按需准备的依赖回退，仅在主 provider 满足回退条件时启动。

Runtime 按 Capability 选择安全引擎，并把不同工具的结果统一为同一种 Finding。

默认情况下不会下载或打包 Semgrep Community / Registry Rules。Semgrep 默认只运行本项目独立编写的本地规则包。

Gitleaks 和 Trivy 的解析顺序：

```text
显式指定路径
    ↓
Runtime 托管版本
    ↓
系统 PATH 中兼容版本
    ↓
自动安装托管版本
```

Offline 模式只禁止新的网络下载，不会禁止使用本机已经存在的兼容工具。

禁止下载：

```text
SECURITY_RUNTIME_OFFLINE=1
```

---

# Coverage 和结果含义

如果部分 Scanner 不可用，AI Security Runtime 不会把这种情况当成“项目安全”。

扫描结果包含 Coverage：

- **NONE / NO_CHANGES**：没有需要检查的变更，没有执行扫描；推荐值为 **NOT_ASSESSED**。
- **FULL**：选中文件上适用的计划检查成功执行，包括代码和 Secret 检查。范围是本次计划，不代表全仓或所有能力。
- **SCOPED**：适用检查执行成功，但代码安全检查不适用，例如仅 Secret 文件变更。
- **PARTIAL**：部分适用检查失败或不可用。
- **MINIMAL**：没有适用检查执行成功。

CLI JSON / MCP 包含 `execution_state`、`coverage_scope: PLANNED_FILES` 和
`capability_results`；`NOT_APPLICABLE` 与失败/不可用明确区分。

Release Status：

- **SAFE**：已经执行的检查在所述范围内未发现策略阻断项。
- **REVIEW**：建议进行人工或 Agent 复核。
- **BLOCKED**：当前策略发现需要阻断的问题。

SAFE 不代表项目绝对安全。

---

# Workspace 安全边界

CLI、MCP Server、Cursor、WorkBuddy 和 pre-commit Hook 使用同一个 Workspace Resolver。

Runtime 会拒绝过大的危险根目录，例如：

- 用户 Home；
- 磁盘根目录；
- Windows 系统目录。

Git 项目 quick/feature 以 Git 变更文件为边界，release 使用有效的 Git 文件列表。
显式文件列表允许超过 12 层；深度和目录数量限制主要用于非 Git 递归发现。
仍保留越界、symlink/junction、最大文件数和文件大小保护。verify 只分析对应文件，
调用原始 Scanner。doctor 遇到 profiling 限制会展示 LIMITED 并继续诊断工具和 workspace。

MCP 日志输出到 stderr，避免污染 stdio MCP 协议使用的 stdout。

---

# 常见问题

### 出现 `No project detected`

请在 Git 仓库中运行：

```bash
git init
security-check doctor
```

或者明确指定项目：

```bash
security-check doctor --path <project>
```

### 某个 Scanner 不可用

正常扫描会自动准备需要的 Managed Tools。

查看状态：

```bash
security-check tools status
```

手动准备全部工具：

```bash
security-check tools install --all
```

### 重新安装 Runtime 后 Cursor / WorkBuddy 配置路径失效

执行：

```bash
security-check integrations repair
```

### 查看更详细的接入信息

```bash
security-check integrations --verbose
security-check doctor --verbose
```

### 删除项目接入

```bash
security-check integrations remove cursor
security-check integrations remove workbuddy
```

只会删除 Runtime 自己管理的 `ai-security-runtime` 配置项。

---

# 本地状态和隐私

扫描历史和 Integration State 保存在用户级本地状态目录。

Windows 默认 Managed Runtime 数据目录：

```text
%LOCALAPPDATA%\AI-Security-Runtime
```

CLI 扫描不需要 AI API Key。

本地使用统计不应记录：

- 完整源码；
- Secret；
- 私有文件正文；
- 完整 Prompt。

---

# CI / 自动化

CLI 是 Runtime 的通用自动化入口，后续可以接入 Jenkins、GitHub Actions、GitLab CI 或其他 CI/CD Pipeline。

基础机器可读调用：

```bash
security-check scan --mode release --json
```

当前仓库自身使用三类 GitHub Actions：

- **Runtime tests**：Windows 和 Ubuntu 自动测试。
- **Compliance**：Engine LicenseMetadata、first-party Rule provenance、禁用规则来源及 Notices 检查。
- **Package integrity**：构建并验证源码包和 Wheel。

---

# 软件许可

AI Security Runtime 采用 **闭源 Core + 开放生态** 模式：

- Runtime Core、Risk/Policy Engine、未来高级规则与 Intelligence：**Proprietary**；
- 公共 Plugin API 和当前基础 `ai-security-core` 规则包：**Apache-2.0**；
- Semgrep、Gitleaks、Trivy 等第三方组件继续遵守各自许可证。

免费使用不等于开源。除明确标注 Apache-2.0 的组件外，Runtime 默认受根目录 `LICENSE` 和 `EULA.md` 约束。

详见 [Licensing model](LICENSING.md)。

---

# Rule 和 License 边界

Engine License 和 Rule Pack License 分开管理。

Runtime 不打包，也不会自动获取 Semgrep Community / Registry Rules。

用户可以运行自己提供的本地规则：

```bash
security-check scan --rules <directory>
```

更多说明：

- [第三方声明](THIRD_PARTY_NOTICES.md)
- [源码可用性说明](SOURCE_OFFER.md)
- [架构说明](docs/ARCHITECTURE.md)
- [扩展指南](docs/EXTENDING.md)

---

## 当前 Developer Alpha 支持情况

| 接口 | 当前状态 |
| --- | --- |
| CLI | 已支持 |
| Cursor 原生接入 | 已支持 |
| WorkBuddy 原生接入 | 已支持 |
| Generic stdio MCP | 已支持 |
| Codex | Generic MCP |
| 其他 MCP Coding 工具 | Generic MCP |
| Git pre-commit | 已支持 |
| CI/CD | 已具备 CLI 基础 |

产品原则：

> **重要平台做 Native，其他平台走 Generic MCP，CLI 作为通用兜底。**

## Development / Contributing

下面的源码安装步骤仅用于开发环境。

### 源码安装

如果你只是想试用，不需要先理解 Python、虚拟环境或 MCP。

你只需要做 3 件事：

```text
1. 安装 Python 和 Git
2. 安装 AI Security Runtime
3. 进入自己的项目，开始扫描 / 接入 Cursor 或 WorkBuddy
```

> 当前还是 Developer Alpha，因此暂时需要 Python 3.12+ 和 Git。正式发布版本的目标会进一步简化为安装包或一条安装命令。

---

### 第 1 步：确认电脑有 Python 和 Git

#### Windows 用户

打开 **PowerShell**：

- 按键盘 `Win`
- 输入 `PowerShell`
- 打开“Windows PowerShell”或“终端”

然后分别输入：

```powershell
python --version
git --version
```

如果看到类似：

```text
Python 3.12.x
git version 2.x.x
```

说明环境已经准备好，可以直接进入下一步。

#### 如果提示“找不到 python”或“找不到 git”

最省事的方式是在 PowerShell 中安装：

```powershell
winget install -e --id Python.Python.3.12
winget install -e --id Git.Git
```

安装完成后，**关闭 PowerShell，再重新打开一次**。

然后重新确认：

```powershell
python --version
git --version
```

> Python 和 Git 只是 Runtime 的运行环境。你不需要会 Python，也不需要会写 Git 命令。

---

### 第 2 步：安装 AI Security Runtime

在 PowerShell 中直接复制下面几行，按回车执行：

```powershell
git clone -b feature/runtime-mvp https://github.com/pikachu-cxy/Ai-security-check.git
cd Ai-security-check
python -m pip install --upgrade pip
python -m pip install -e ".[test,scanner-test,build-standalone]"
```

这里每行的意思分别是：

| 命令 | 作用 |
| --- | --- |
| `git clone ...` | 下载 AI Security Runtime |
| `cd Ai-security-check` | 进入下载好的目录 |
| `python -m pip install --upgrade pip` | 更新 Python 安装工具 |
| `python -m pip install -e ".[test,scanner-test,build-standalone]"` | 安装 Runtime 和 MCP 能力 |

正常情况下，你不需要修改这些命令。

安装完成后执行：

```powershell
security-check --help
```

如果看到：

```text
usage: security-check ...
```

说明安装成功。

---


发行构建、验证与首次外部发布步骤见 [distribution staging](distribution/README.md)。
## 扫描失败与普通源码目录

`doctor` 用 `READY` / `MISSING` 表示本地执行前提。READY 表示所需本地引擎条件已就绪；项目扫描仍可能依赖远程仓库或项目依赖解析，不能保证任意扫描成功。

`doctor --verbose` 与 `tools status` 分别展示 Trivy Vulnerability DB、Java DB 和 checks 状态。Java DB 按本地文件显示 `READY` / `MISSING`，checks 保守显示 `UNKNOWN`。本轮不自动下载 Java DB 或 checks；Maven 仓库 HTTP 429 会独立报告为 `MAVEN_RATE_LIMITED`，不会归因为漏洞库缺失。

普通源码目录支持 `security-check scan --path <directory> --mode release`；安全识别到当前源码目录时，也支持直接运行 `doctor` 和 release。quick、feature、staged 仍要求 Git，并提示改用 release。Git 项目优先使用 Git 文件列表；普通目录采用有界递归发现，保留文件数、目录数、深度、大小、忽略目录以及 Home、系统目录、盘符根、symlink/junction 边界。

扫描器错误包含 `error_code`、`error_summary`、`remediation`、可选 `retry_after_seconds` 和有界脱敏的 `diagnostic_detail`。CLI JSON 和 MCP 使用相同结构，不保存或返回原始大段 stdout/stderr。URL 仅保留主机名，凭据和 Authorization 脱敏；代理只显示 configured / not configured。

能力状态：所有计划 provider 成功为 `EXECUTED`；成功与失败/不可用/超时并存为 `PARTIAL`；没有成功且存在执行失败为 `FAILED`；均无法执行为 `UNAVAILABLE`；scope 不需要为 `NOT_APPLICABLE`。部分覆盖下，已完成检查的 findings 仍有效，其他问题可能尚未检出。准备失败会提示 `security-check tools install <engine>` 重试；Maven 限流建议本地缓存、mirror 或等待后重试。Runtime 不会自动执行目标项目的 Maven、Gradle、npm、pip、go 构建或依赖命令。

## 依赖 Provider 与按需回退

默认敏感信息能力由 Gitleaks 独立提供。Trivy 依赖进程失败不会影响单独执行的 IaC 检查。Maven 429、网络超时、DNS／代理失败、HTTP 5xx、依赖解析失败或引擎不可用可以触发 OSV；完整性、路径边界、配置损坏和内部 invariant 错误不会被自动回退掩盖。

依赖能力由覆盖契约决定：一个 provider 成功且满足本次完整锁文件范围的 FULL 契约即可 EXECUTED，即使主 provider 曾失败。只有直接清单或未证明完整依赖图的 POM 结果保持 PARTIAL。JSON／MCP 的 `capability_details` 保留 active provider、role、coverage 和主 provider 诊断。

`tools install --all` 只准备默认主引擎；OSV 在 `tools status` 中显示 `ON_DEMAND / FALLBACK`，不影响 doctor 的默认就绪状态。`tools install osv-scanner` 可显式准备固定版本和官方 SHA-256 校验的二进制。在线 OSV 会向 deps.dev／OSV.dev 查询依赖名称与版本。离线执行必须已有引擎和 `<data-dir>/data/osv/osv-scalibr/<ecosystem>/all.zip` 数据，不会自动下载。调用图分析和目标构建均关闭，Runtime 不修改 Maven settings 或自动添加 mirror。

验收记录：[Trivy 能力解耦](docs/TRIVY_CAPABILITY_DECOUPLING.md)、[OSV 依赖回退](docs/OSV_DEPENDENCY_FALLBACK.md)。

## Finding Triage v0.1

扫描发现的是候选安全问题。Raw Findings 永久保留；验证结果作为独立 TriageRecord 保存，Scan Coverage 与 Triage Coverage 分开。IaC 本轮只做规则 ID 分类。

```text
security-check scan --mode release
security-check triage --latest
security-check triage --latest --prepare --category code --limit 20
security-check triage --latest --raw
```

先从当前项目取得建议跟进任务，无需手工寻找扫描 UUID：

```bash
security-check summary --path <project>
security-check summary --path <project> --details
security-check summary --path <project> --json
```

普通视图最多推荐三项，详细视图保留完整任务、每条候选/advisory、审阅状态和 Raw 入口。只读汇总不扫描、不调用 AI、不改 DB/源码；无记录仅建议首次检查。扫描覆盖与 AI 审阅覆盖分开，VALID 表示“已完成 AI 审阅”，不等于人工验证或线上可利用。建议核查 REVIEW 不会把它升级为 ACTIONABLE；0 ACTIONABLE 不表示安全。

绑定项目的 MCP 可直接调用 `get_security_summary`，`details=true` 展开全部；未绑定时必须明确 `workspace_path`。后续核查/修复尚未内置。本轮三位真实开发者试用仍待验收，参见 PROJECT_STATE/NEXT_STAGE。

Coding Agent 可用 MCP `prepare_triage` 获取限定、脱敏的 UNTRUSTED_CODE 证据，使用自己的模型分析，再携带返回的 triage_session 调用 `submit_triage`；`get_triage` 返回独立覆盖和分组视图。

BYOK 为 OpenAI-compatible 用户 provider：

```text
security-check ai configure --base-url https://provider.example/v1 --model user-model --api-key-env SECURITY_RUNTIME_AI_KEY
security-check triage --latest --provider configured --allow-external-code-context --category code --severity HIGH --limit 20
```

实际 key 只从环境变量读取。普通 scan 不调用 AI；外部代码上下文必须显式授权，无授权 fail closed。Secret 值不进入 EvidencePacket，源码与注释只作为不可信数据；FALSE_POSITIVE 需要严格明确反证，不能因 docs/example 或未搜索到 API 自动隐藏。详见 [AI Triage 验收](docs/AI_TRIAGE_ACCEPTANCE.md)。


继续核查 v0.1：MCP 当前11个工具，新增 `prepare_task_triage`。用户看到汇总后说“继续第一项”，宿主使用**实际展示响应**中该项的 `continuation.arguments`，不能把 T01 当稳定身份或重新取第一项。得到受限 packet 后沿 `submit_triage` 提交，Runtime 不调用宿主模型。有效审阅保留，缓存不占新分析名额，STALE 重建、FAILED 仅 `retry_failed=true` 显式重试。任务变化/引用无效要求刷新重新选择；不存在自动补丁或目标构建。三位真实开发者试用仍待验收。
