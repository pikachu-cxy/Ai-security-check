# 开发交接

更新日期：2026-10-22。当前产品 0.3.9 正式版，分支 `feature/runtime-mvp`；程序包源码为 `fa1a26b`，Mac 独立安装为 `macos-trial-v0.3.9.3`。当前用法、语言覆盖和发布事实见[开发进度](DEVELOPMENT_PROGRESS.md)及[产品覆盖](PRODUCT_COVERAGE.zh-CN.md)。下述架构与恢复约束继续适用，历史测试与会话状态不继承为新任务结论。

## 恢复工作前

1. 核对 git status、当前分支和远端；保护用户已有修改。
2. 从实际 get_runtime_info 核对 build_id、task-review-plan-v3、task-result-delivery-v1 和九项任务工具。源码、安装包、运行进程分别认定。
3. 开发任务在首次新编辑前保存真实基线；已有合法任务沿原引用继续，不按最近任务猜测。旧 v1/v2 仅供历史读取。
4. 原始会话、任务/风险引用及安全状态保留在 Runtime 私有目录，不复制进仓库作为恢复文件。

## 当前实现边界

- 连接：WorkspaceApplication 和 workspace_services 装配原服务，MCPRegistry 负责 SDK / 原始输入边界，连接器只适配事件和输出。
- 执行：ScanRequest / CapturedScanInput 固定源码及执行身份；ScanAttemptStore 管理独立租约、代际、取消和发布条件。
- 恢复：scan_publication 保存有界签名完成事实，TASK / Hook 在原代际下恢复发布；不创建第二套扫描引擎或编辑权限。
- 交付：当前结果沿终态回执的 completion_revision 与原 session_ref 读取；普通历史省略该选择器，不重放修复选择。
- 处置：AI 技术评估、EXCLUDE / DEFER / RESTORE、提醒与修复证明分开；查询失败不能把未知决定当成新待处理项。
- 修复：原生风险与扫描器发现使用各自原引用；影响分析只读，已有明确授权在原范围内保留。新任务零发现不能关闭旧风险。

私有扫描状态新写 v2，兼容已签名 v1 的读取及旧根清理；执行 receipt 仍 v1。降级需核对 storage_contracts，不删除历史、围栏或用户 Skill。

## 当前验证与待办

已记录的定向回归、当前同步验证和跳过原因见[验收记录](RUNTIME_CHAIN_REGRESSION_ACCEPTANCE.zh-CN.md)。前一冻结全库及候选身份见[架构记录](ARCHITECTURE_UNIFICATION_COMPLETION.zh-CN.md)，不直接转用于新改动。

三平台正式包已发布；本轮文档提交不构建或替换安装包，也不自动重装当前接入。完整桌面验收按真实平台、宿主与构建分别记录，不用旧会话或历史候选结果代替。

下一步先完成 Codex 样例验收，再按冻结提交构建独立候选及跨宿主验证。新增能力只按真实证据承诺，见[计划](NEXT_DEVELOPMENT_PLAN.zh-CN.md)和[宿主状态](HOST_SUPPORT.md)。

## 开发环境命令

在仓库根目录，使用 Python 3.12+：

~~~powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[test]"
.\.venv\Scripts\python.exe -m pytest -q
git diff --check
~~~

测试使用隔离的 TEMP、状态目录和合成源码；不连接用户真实样例或修改实际配置。Windows 本地套接字与 ACL 测试需在正常用户环境运行，不能通过放宽产品权限边界绕过工具沙箱限制。

自动回归依赖的 fixture、兼容旧 writer 语料和对照数据保留。旧阶段教程和无引用手工实验从当前树删除，历史通过 Git 查阅；本机 artifacts、dist、缓存与状态仍为忽略内容，不上传。
