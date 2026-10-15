# 发布下载区补丁复核

基线：`feature/runtime-mvp` 的 `755e411c4383003a5da54330890fb49c6f96c967`。原下载区补丁只调整后续发布展示与资产布局，不修改版本号。现整合至 0.3.4 本地组合候选；本文和[脚本生成的发布说明示例](RELEASE_DOWNLOADS_EXAMPLE.zh-CN.md)使用 0.3.4 文件名，仅供复核，不表示已经发布。不会改写已公开 0.3.3 标签或资产；脚本仍从单一版本源生成链接。

组合验证：在原性能本地候选 d2ae7d3 上应用已复核下载区提交 86201df 的六文件补丁，无内容冲突。相关下载资产、发行一致性、性能报告、新鲜度及源身份定向测试共 46 passed（20.38 秒），日志和 JUnit 保存在组合任务的隔离证据目录。0.3.4 静态示例与实际夹具生成的 release-notes.md 逐字节相同。性能 Runtime 源码未改，原局部分页数据不泛化为组合版本或整体体验提速；本轮不更新当前 PR #1、不推送或发布，先交组合复核。下文 16 项记录属于原下载区任务的历史验证，不冒充本轮完整 CI 或真实包验收。

## 预期公开 Assets

共九项，另有 GitHub 自动提供的两个 Source code 压缩包：

```text
ai-security-runtime-v0.3.4-windows-x64.zip
ai-security-runtime-v0.3.4-windows-x64.zip.sha256
ai-security-runtime-v0.3.4-macos-arm64.tar.gz
ai-security-runtime-v0.3.4-macos-arm64.tar.gz.sha256
ai-security-runtime-v0.3.4-macos-x64.tar.gz
ai-security-runtime-v0.3.4-macos-x64.tar.gz.sha256
ai-security-runtime-v0.3.4-release-evidence.zip
SHA256SUMS.txt
release-manifest.json
```

普通用户在发布说明顶部直接点 Windows、Mac Apple Silicon 或 Mac Intel 安装包，旁边有选型与校验入口。维护者材料收在折叠说明和一个证据 ZIP 中。保留 README 要求的同名 `.sha256`，机器 manifest 也保留为公开独立文件。

## 证据与消费者确认

全仓搜索确认，`verify_artifact.py` 产出每包 `.verification.json`；`make_release_metadata.py` 在打包证据前逐包读取，核验 archive SHA256、版本、平台、同提交、smoke、managed engines 与 plugin discovery。此脚本未修改。

`update_homebrew_formula.py`、`generate_winget_manifest.py` 和 `validate_manager_metadata.py` 读取 `release-manifest.json`；原生安装包名称、URL、manifest 内容和这些消费者均未修改。新 staging 脚本也读取该 manifest，核对安装包与独立、汇总校验文件一致。

专项 `.osv-fallback.json`、`.fix-verify.json`、`.hooks.json`、`.remediation.json`、`.confirmation-restart.json`、`.functional.json`、`.codex-integration.json` 没有其他仓库内按发布下载 URL 消费的程序。所有专项和原生 JSON 原样收进证据 ZIP 的 `release/`，安装指南也在同目录；Homebrew Formula 和三个 WinGet YAML 保留 `distribution/` 相对路径。其余未来新增验收文件也自动收进 ZIP。原始 CI artifacts 与 `dist/release` 文件均不移动、不删除。

tests → compliance → package → build → publish 的依赖关系、三平台矩阵和完整 `--full --osv-fallback --fix-verify --hooks --remediation --codex-integration` 验收保留。所有 metadata 生成及 manager validation 通过后才 stage；公开上传仅使用全新 `dist/public-release/*`。`SHA256SUMS.txt` 在公开副本增加证据 ZIP 校验，原始汇总文件不改。

## 本地验证与范围

已执行：`python -m pytest tests/test_release_assets.py tests/test_distribution.py -q --basetemp .test-tmp-release-downloads-unrestricted --tb=short`，`PYTHONPATH=src;.`，结果 **16 passed**。新增测试使用三平台合成字节夹具，经实际 metadata、Homebrew、WinGet 与 vendored schema validation 链路；验证 24 份 JSON 与指南/包管理材料逐字节保留、九项资产、所有链接和 ZIP checksum、损坏/缺失输入阻断、旧提交验收阻断及 workflow 门禁顺序。另执行 `git diff --check`。

最初 sandbox 执行出现 pytest 默认 Temp 路径不可写，显式 workspace basetemp 后 14 passed / 2 failed，失败为子进程路径可见性及硬链接限制；在已批准的隔离任务目录无 sandbox 限制运行同一测试，16 项全部通过。

未覆盖：真实三平台重新构建及原生完整验收、GitHub workflow 在线运行、实际 Release Markdown 页面渲染、公开上传/下载、真实安装或包管理器安装升级。示例由合成夹具生成，未将夹具安装包提交或发布。当前版本号未改，需父任务决定后续版本再接入；已有 draft 若含旧资产，本补丁不会主动删除它们，应使用后续新版本的新 draft。未操作 v0.3.3 运行中的发布、已发表资产、默认分支、性能分支或 PR #1；未推送、合并、打标签或发布。

基线没有仓库根 AGENTS.md、`.agents`、`.codex` 或开发用 skills 说明；已阅读根 README、distribution README、相关候选发行说明与工作流。`src/security_runtime/skills/ai-security-review` 是产品交付 Skill，与发布资产重组无关，未改。
