# AI Security Runtime

[English](README.md) | **简体中文**

> **Agent writes. Security Runtime verifies.**  
> AI 负责编写，Security Runtime 负责验证。

AI Security Runtime 是一个面向 AI Coding 工作流的本地优先安全运行时。它可以检查 AI 编程 Agent 生成或修改的代码，并通过 **CLI** 和 **MCP** 向开发者与 AI Coding 工具提供统一的安全能力。

- **本地优先**：项目源码默认保留在本机。
- **一条命令接入**：原生支持 **Cursor** 和 **WorkBuddy**。
- **通用 MCP**：Codex 等其他支持 MCP 的 AI Coding 工具也可以接入。
- **CLI**：不依赖任何 AI Coding 工具，可独立使用，也适合后续接入 CI/CD。
- **不虚报安全**：如果部分扫描能力不可用，会降低 Coverage，而不是把项目误判为安全。

> 当前为 Developer Alpha。PASS 仅表示当前检查未发现阻断项，不代表项目绝对安全。

---

## 5 分钟快速开始

### 环境要求

- Windows、Linux 或 macOS
- Python **3.12+**
- Git

当前 Developer Alpha 位于：

`feature/runtime-mvp`

### 1. 安装

#### Windows PowerShell

```powershell
git clone -b feature/runtime-mvp https://github.com/pikachu-cxy/Ai-security-check.git
cd Ai-security-check

py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1

python -m pip install --upgrade pip
pip install -e ".[mcp]"
```

#### Linux / macOS

```bash
git clone -b feature/runtime-mvp https://github.com/pikachu-cxy/Ai-security-check.git
cd Ai-security-check

python3.12 -m venv .venv
source .venv/bin/activate

python -m pip install --upgrade pip
pip install -e ".[mcp]"
```

确认 CLI 已安装：

```bash
security-check --help
```

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

第一次扫描可能会自动下载固定版本的 Gitleaks 和 Trivy，并准备 Trivy 漏洞数据库。下载内容会在执行前进行校验，不需要修改系统 PATH。

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
✓ Runtime verified for Cursor
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
- **Trivy**：依赖漏洞及相关项目安全检查。

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

- **FULL**：计划中的安全检查均可执行。
- **PARTIAL**：部分检查不可用。
- **MINIMAL**：只有有限安全能力可用。

Release Status：

- **PASS**：当前检查未发现策略阻断项。
- **REVIEW**：建议进行人工或 Agent 复核。
- **BLOCKED**：当前策略发现需要阻断的问题。

PASS 不代表项目绝对安全。

---

# Workspace 安全边界

CLI、MCP Server、Cursor、WorkBuddy 和 pre-commit Hook 使用同一个 Workspace Resolver。

Runtime 会拒绝过大的危险根目录，例如：

- 用户 Home；
- 磁盘根目录；
- Windows 系统目录。

项目发现过程会跳过生成目录和依赖目录，并限制最大文件数、目录数、深度和单文件大小。

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
