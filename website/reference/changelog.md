# 版本与进度

## 0.3.6 · Developer Alpha

2026-10-19 已公开发布 [v0.3.6 Developer Alpha](https://github.com/pikachu-cxy/Ai-security-check/releases/tag/v0.3.6)，原始版本标签与 Windows 包对应提交 `b4fa0ab086866f5db5c59b8f5f74ec180ed43f23`。Mac 后续兼容修订分别记录源码与原生验收，不因版本号相同就认为构建相同。

### Mac 安装兼容修订

系统证书/代理、临时路径别名、受校验 Python 引导、首次启动时限及组件安装失败恢复均限定 Mac；Windows 继续原安装行为。本轮只验收 Mac 与 Windows。Intel 与 Apple Silicon 原生验收通过后，按用户要求替换 v0.3.6 对应 Mac 资产，并同步校验清单和 Mac 证据，Windows 资产及版本标签不移动。完成状态以[下载页](../downloads.md)和 `macos-refresh.json` 为准，签名、公证与浏览器首次运行另行验收。

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
