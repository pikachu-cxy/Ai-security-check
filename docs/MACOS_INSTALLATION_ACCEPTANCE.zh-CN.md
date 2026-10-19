# macOS 安装优化与验收

更新：2026-10-19。当前修订仅限 Mac，Windows 保持原安装行为。本地通过、源码推送与 Release 资产替换分别记录。

## 同类工具的安装方式

| 官方来源 | 已核对做法 | 本项目的借鉴方向 |
| --- | --- | --- |
| [Semgrep](https://semgrep.dev/products/community-edition/) | Mac 的 CLI 入门推荐 Homebrew | 可提供包管理器入口；不把用户系统 Python 当作默认前提 |
| [Snyk CLI](https://docs.snyk.io/developer-tools/snyk-cli/install-the-snyk-cli) | Homebrew/npm 等包管理器，以及按系统和架构下载独立程序；另有校验指引 | 明确架构、发行来源、完整性核验和版本检查 |
| [Trivy](https://www.trivy.dev/docs/latest/getting-started/installation/) | 官方 Homebrew、GitHub Release 与安装脚本；标注官方和社区渠道 | 将下载、准备和运行分开，清楚标识受支持入口 |

这些文档不能证明各工具所有 Mac 包都已签名或公证，也不能据此认为 Homebrew 自动解决 Gatekeeper。Apple 信任链仍按 [Developer ID 与公证要求](https://developer.apple.com/developer-id/)单独处理。

本项目保留完整包入口，新增可复制的 Codex 安装请求；Homebrew 外部上架与图形安装器仍是后续发行工作。无需安装 Homebrew 才能使用当前完整包。

### 建议采用的发行顺序

1. **当前：同一安装器支持两种操作方式。** 文档主入口复制安装请求给本地 Codex，手动入口使用同一份完整发行包。两种方式都要核对系统、芯片、包校验和安装结果，不能让辅助安装偷偷改成源码环境。网站只复制请求，不获得本地执行权限。
2. **正式 Mac 发行：签名和公证优先。** 使用 Developer ID 对程序和内嵌 Python、动态库完成正确签名，再对支持的发行容器公证。若采用 PKG，安装包签名也需相应证书。CI 应保存签名、公证结果，并验证浏览器下载和解压后的首次运行；单独对启动器签名或本机无隔离标记的执行不够。
3. **开发者渠道：维护官方 Homebrew tap。** 指向同一份经过验收的版本包，固定 URL、芯片选择和 SHA256，明确升级与卸载方式。先保证底层包可靠，再增加渠道；Homebrew 本身不是本项目获得 Apple 信任的凭据。
4. **更广泛用户：再考虑签名 PKG 安装向导。** 让向导显示目标宿主、下载准备进度、失败重试与最终状态，并提供卸载入口。是否支持当前 Intel/Apple Silicon 与最低 macOS 版本，都应有真机或 CI 验证记录，不能只按构建文件名推断。

验收应覆盖三条实际路径：新用户空配置和空组件数据、旧版本升级且保留其他 MCP 配置、卸载后手动重装。首次规则/漏洞库下载单独展示进度；配置写入成功不能冒充检查组件已全部就绪。

## 当前 Mac 改进与平台边界

- 仅为安装器创建的临时目录和系统默认临时根处理 macOS 路径别名；显式配置路径与任意链接仍拒绝。
- macOS 下载及工具子进程采用系统 CA 默认值；保留用户证书覆盖与 TLS 验证，传递已有系统代理，不写死本机代理端口。
- Mac 源码 Semgrep 与冻结包使用同一受校验 CPython 引导环境，避免复制可重定位 Python 后丢失动态库。
- 仅 Mac 默认联网安装 Semgrep 接受 wheel，避免隐式引入 Rust 编译；Windows 原 pip 参数不变。
- 仅 Mac 的 Python 组件安装加跨进程互斥，失败恢复旧目录；Windows 继续原安装路径。绝对路径不能通过简单重命名 staging 虚拟环境改变，否则脚本 shebang 会失效；当前实现不宣称无中断原子升级。
- 仅 Mac 环境创建异常保留动态库或签名错误类别，不回显原始路径、凭据或日志；其他平台继续原诊断。
- Mac Semgrep 首次启动的版本校验上限从 8 秒调整为 30 秒；保留其他平台和组件的原有时限，校验失败保留具体诊断。
- 文档首页、快速开始和安装页提供安装请求按钮；剪贴板被拒绝时显示可手动复制的正文。Codex 辅助安装在最后重启生效。

Windows 同时保持原有临时探测目录校验、子进程环境和首次启动时限。平台分支测试验证兼容约束，真实 Windows 回归和两种 Mac 原生包验收仍由相应 runner 分别执行。本轮不增加 Linux 构建或验收。

## v0.3.6 Mac 资产替换

使用当前干净源码提交的 Intel 与 Apple Silicon 原生包及其验收回执。只有 Windows/Mac 回归和原生包验收完成后才更新 Release；现有 Windows ZIP、SHA256 文件的资产 ID 和摘要必须保持不变。原始版本标签不移动，机器清单保留原始 `source_commit` 并另以 `artifact_source_commits` 记录各平台来源，避免把新版 Mac 来源错误套给 Windows。

显式发布提交标记 `[refresh-macos-v0.3.6]` 启动一次受约束的替换流程；普通源码推送不触发已发布资产覆盖。旧版资产 ID/摘要固定在 `distribution/releases/v0.3.6-macos-refresh.json`。发布前保存旧资产及精确待发布内容的 Actions 备份，随后只替换 Mac 包/侧车与共享清单、证据 ZIP，增加 `macos-refresh.json`，保留 Windows 证据。共享证据内的 Homebrew 示例更新为新 Mac 摘要，WinGet 保留原内容。GitHub 多资产操作不是原子事务；失败沿同一准备产物重试，发现未知的并发变动则停止。

收敛后本地安装相关回归：182 通过、13 跳过；发行替换及既有元数据相关回归：22 通过。对应 `artifacts/mac-only-regression.xml` 与 `artifacts/mac-release-refresh-tests.xml` 仅保存在本地，不随源码发布。公开资产更新状态以 Release 的 `macos-refresh.json` 及 Actions 原生验收为准。

## 必须保留的边界

本机没有可用的 Apple 代码签名身份。本轮不能完成 Developer ID 签名、公证或浏览器下载后的 Gatekeeper 放行验收；不删除隔离标记来声称这些环节通过。新本地候选仅用于本机手动回归，不能替代正式签名发行。

先在隔离用户配置与独立数据目录中验证候选，不覆盖真实安装。回归和包检查完成后，使用产品卸载入口移除本机 MCP、受管 Hook 和受管 Skill，保留用户其他配置、历史和组件缓存，供用户手动安装。保留缓存的重装不等于新机器冷安装；独立空目录的组件验收另存回执。

## 前轮本地候选验证记录（收敛前历史）

实际测试、原始失败、候选身份与卸载回执保存在本地 `artifacts/`。只有相应命令和回执成功后才记录通过；签名、公证、ARM 真机及当前聊天重连不由单元回归或 Intel 本地包推定。

- 初轮相关回归：322 通过、14 跳过，`artifacts/mac-install-regression-complete.xml`。这些结果与后续补充回归有重叠，不能相加。
- 文档本地构建成功，浏览器实际点击按钮显示复制成功；截图 `artifacts/mac-docs-install-button.png`。文档发布提交 `f6d93bdd48dc54b41e92d3b6e48387aa425a9b17`，GitHub Pages 工作流 `39258209874` 成功；线上首页包含安装请求入口。
- 第一份本地候选 r3 冷安装：程序与隔离 Codex 配置写入成功；Gitleaks、Trivy 与全新漏洞库准备成功，Semgrep 首次启动超时，整体为 PARTIAL，不能认定通过。见 `artifacts/mac-cold-install.json`、`artifacts/mac-cold-preparation.json`。
- 追查结果：实际下载和 pip 安装均返回 0；首次版本探测在 8.01 秒超时，随后允许更长等待的探测成功返回 1.178.0。见 `artifacts/mac-semgrep-probe-timing.log`。补充修复后重新打包验收，不以预热旧包冒充新包冷安装。
- 启动时限与缓存相关补充回归：84 通过、1 跳过，`artifacts/mac-startup-regression.xml`。包含新增时限测试、Python 引导、组件健康、进程缓存与执行身份相关验证。
- 最终候选 r4：构建 `757dc0fa4423aa28d47ae4ee87387a9f649e6e742254230d37bdbdf53dce56b7`，版本 0.3.6，来源提交 `f6d93bdd48dc54b41e92d3b6e48387aa425a9b17` 加本地未提交安装器改动（`source_dirty=true`）。程序和包内 272 个文件通过清单校验。压缩包 SHA256 为 `75e5284930ac61363736cb3d2e4a050a4f04641fb8e7ad782f164e5a9c1cd442`；重新解压后再次通过清单校验并正常启动。见 `artifacts/mac-local-candidate.json`、`artifacts/mac-local-archive-verification.json`。
- r4 实际冷安装：新的隔离 Codex 配置、独立空组件目录，路径含中文和空格；未显式注入 CA、代理或外部 Semgrep 路径。安装返回 0，后台准备约 122 秒后返回 0，Semgrep 1.178.0、Gitleaks 8.30.0、Trivy 0.74.0 均 READY，漏洞库 READY/FRESH、失败列表为空。使用真实官方安装来源，未复用本机产品组件目录；pip 下载缓存、操作系统及网络缓存未清空，不等于全新操作系统验收。见 `artifacts/mac-cold-r4-install.json`、`artifacts/mac-cold-r4-preparation.json`。
- 接入核对须调用**安装后的稳定启动入口**。最初从下载目录执行状态查询返回 RUNTIME_STALE，是查询入口与安装入口不同，不是组件准备失败；原始回执 `artifacts/mac-cold-r4-status.json` 保留。从已安装启动入口重查返回 CONFIGURED、OWNED_AND_CURRENT，MCP 与 Hook 配置完成、诊断为空，Skill 状态查询成功；见 `artifacts/mac-cold-r4-installed-status.json` 等文件。真实 Codex 重启后的连接仍待用户手动安装后确认。
- 本轮开发安全任务未建立：修改前调用当前已连接 Runtime 的任务入口时，发生 `RUNTIME_WORKFLOW` 模块导入错误，未获得 task_ref。没有事后重建基线，也未把测试结果冒充任务安全核查结果。
- 本机原安装已卸载：官方卸载入口返回 REMOVED，Skill 移除返回 REMOVED；只在确认没有原安装目录下的产品进程后，把原程序移至 `artifacts/mac-local-uninstall/program-backup` 可恢复备份。最终产品状态和 Skill 状态均 NOT_INSTALLED。与卸载前备份逐项比较，其他 Codex 配置、其他 Hook 和组件路径配置保持不变，组件数据与历史未清空。见 `artifacts/mac-local-uninstall/verification.json`。
- 用户手动重装入口为 `dist/mac-local-20261019-r4/security-check/security-check install codex`，完整说明见 `dist/本机手动安装说明.txt`。本轮结束前未替用户重装，也未自动退出或重启当前聊天。网站按钮指向公开发行包，本地候选尚未上传覆盖公开包。
