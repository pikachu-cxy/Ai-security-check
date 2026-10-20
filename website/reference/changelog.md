# 版本与进度

## 0.3.8 · Developer Alpha

2026-10-20：[0.3.8 发布构建](https://github.com/pikachu-cxy/Ai-security-check/actions/runs/39386551651)已通过，[v0.3.8 Release](https://github.com/pikachu-cxy/Ai-security-check/releases/tag/v0.3.8)已公开九项资产。Windows、Mac Apple Silicon 与 Mac Intel 使用同一版本及发布提交 `be65833`，下载及校验入口见[下载页](../downloads.md)。

- 工作流指导按需加载、去重，并按版本、摘要和实际构建身份复用已读内容。
- MCP 接通共用扫描阶段进度与计时，区分本次核验、历史扫描和宿主侧未知耗时。
- 支持明确指定工作区相对文件，展示实际范围，不把单文件请求扩大为整项目。
- 完整项目扫描仅在源码、规则、引擎、配置及数据身份等证明有效时复用结果；无法核验或明确要求重扫时重新执行。
- 保留必要复核与修复授权。Windows/macOS、Codex/Cursor 共用核心逻辑，进度显示由宿主能力决定，不沿用旧包的原生或桌面验收结论。
- 修正 wheel 验证脚本对旧指导文案的断言，继续检查当前的编辑授权约束。
- 本次采用精简发布流程，通过 Windows/macOS 相关回归、合规、包完整性及三平台原生验收；未重复执行全库回归。README、下载页、工作流程及 Cursor 指南同步为已发行状态。

## 0.3.7 · Developer Alpha

2026-10-20：[0.3.7 发布构建](https://github.com/pikachu-cxy/Ai-security-check/actions/runs/39365932407)已通过，[v0.3.7](https://github.com/pikachu-cxy/Ai-security-check/releases/tag/v0.3.7)的九项资产已公开，下载及校验入口见[下载页](../downloads.md)。Windows、Mac Apple Silicon 与 Mac Intel 使用同一版本和同一发布提交 `96ade76`。

- 收窄源码证据脱敏，保留普通字符串、注释、字段名及普通网址，对识别出的密码、令牌和私钥等凭据值继续脱敏；Windows/macOS 共用同一规则。
- 必需源码窗口未读完或复核单元未提交时要求 Agent 继续，防止 Git 拉取或正常开发后提前结束复核。
- 新任务使用新脱敏策略，旧任务保留原策略和比较记录，不重建历史证据。
- 本次复用已完成的 697 项相关开发回归及补充边界验证，在 GitHub 运行 Windows/macOS 精简回归，并保留合规、包完整性和三平台原生验收。未重复执行全库回归。
- README、下载入口、隐私、工作流程和常见问题同步更新；更新安装后仍需重新连接宿主。

## 0.3.6 · Developer Alpha

2026-10-19 已公开发布 [v0.3.6 Developer Alpha](https://github.com/pikachu-cxy/Ai-security-check/releases/tag/v0.3.6)，原始版本标签与 Windows 包对应提交 `b4fa0ab086866f5db5c59b8f5f74ec180ed43f23`。Mac 后续兼容修订分别记录源码与原生验收，不因版本号相同就认为构建相同。

### Mac 安装兼容修订

2026-10-20：系统证书/代理、临时路径别名、受校验 Python 引导、首次启动时限及组件安装失败恢复均限定 Mac；Windows 继续原安装行为。干净提交 `c1641b7` 已通过同提交全量回归（Mac 5,086、Windows 5,103 项通过，跳过与预期失败见 CI）和三套原生包验收，v0.3.6 的 Intel 与 Apple Silicon 包已替换，并核对公开下载。配套校验、Mac 证据和 Homebrew 示例同步更新；Windows 原包、WinGet 内容及版本标签保持不变。详情见[下载页](../downloads.md)和 `macos-refresh.json`，本轮不增加 Linux 交付。

文档首页、快速开始和安装页已提供“复制安装请求”按钮，可交给本地 Codex 使用公开完整包安装；手动安装入口保留。Apple 签名、公证与浏览器首次运行仍待完成，“未知开发者”提示尚未从发行流程根治。

这一源码阶段包括：

- v3 任务复核与风险交付能力，保留基线、改动、处置和恢复链。
- Windows 扫描私有输入长路径处理、Semgrep 短临时目录与有界就绪探测。
- 初始化、发布锁竞争、中断和取消后的恢复；沿原任务恢复已完成结果。
- 风险说明、技术评估与用户处置投影；读取失败时保留未知。
- 受管 Skill 升级时处理已退役方法文件并保护用户修改。

本次发布工程改动修正包验证脚本对新 Skill 布局的过期假设：逐一检查当前受管文件的标准内容，拒绝缺失、修改或退役方法残留，不跳过一致性校验。

## 文档站建设

新增产品介绍、快速开始、默认完整安装、手动 MCP、工作流程、风险处置、支持状态、隐私、常见问题、下载状态和 GitHub Pages 部署说明。

2026-10-19：GitHub Pages 首次部署成功。修正 macOS 托管解释器链接的身份绑定、Cursor 基线捕获失败处理、合成项目与私有状态隔离，以及新版修复前影响分析和结果交付契约。Windows 全量测试 5075 项通过、macOS 5054 项通过（各自的平台跳过与预期失败见 CI 记录）；规则质量、合规、包完整性及三平台原生完整验收均通过后发布 Release。CI 合成场景不冒充桌面手工验收。

## 仍待交付

- 本次版本 macOS 真机与 Cursor 桌面手工验收。
- 在线 / 本地漏洞库双模式、一条命令安装等安装体验优化。

这些不是本版现有功能。公开下载状态以[下载页](../downloads.md)为准，完整工程记录见 [开发进度](https://github.com/pikachu-cxy/Ai-security-check/blob/feature/runtime-mvp/docs/DEVELOPMENT_PROGRESS.md)。
