# 优化范围与产品复核说明

## 已实现

源码仅修改 task_security.py：当前上下文 raw 的 SHA-256 算一次；capture 增加默认开启的 include_text，只有 _fresh 传 False。_fresh 仍按当前 Git 清单、排除配置、同样优先路径与文件/字节/时间预算，使用 WorkspaceReader 的完整路径、链接、大小、二进制、打开前后版本与内容读取保护，重新哈希所有当前文件。begin/finish 保存的脱敏前后文本、请求文件单独读取/哈希/脱敏和展示截断判断保持原流程。

没有新增跨调用文件缓存或扫描证据缓存。没有采用 mtime、TTL 或无 Hook 事件来跳过内容读取。既有 finish 幂等保留，Hook revision/失败回执继续参与 freshness 与最终范围；没有改动任务末次静态兜底或静态零告警的上下文复核。此优化不减少分页每次的项目盘点及文件 I/O，也不减少返回文本、模型 token 或扫描器执行次数。

接近 capture 时间预算时，较快的 freshness 读取可能取得比原末次 snapshot 更完整的 hash 集合；两者不等会保守地判 STALE，而不是扩大旧证据的有效性。没有用残缺快照宣称完整。

## 回归证据

107 passed, 1 skipped，353.47 秒。回执 perf-regression.xml 保存在隔离工作区外层。范围：新增六个 freshness 回归、task_security、task_security_inventory、task_hook_deferred_feedback、scan_freshness、cache_lifetime。

包括同大小外部改动并保留 mtime、无 Hook 的连续最后编辑与撤销、Hook 保留路径和失败回执、分页超读/字节/唯一证据预算、读取失败、未读页强制 PARTIAL、零静态告警仍需上下文、显式修复权限边界、规则/配置与排除更新、既有扫描缓存的工作区和来源身份隔离。新增配置回归涵盖样本内规则/配置及当前排除环境；scan_freshness/cache_lifetime 另外核查既有外部规则与扫描准备缓存。没有新增任何规则外部更新后的任务扫描结果复用机制。

跳过：test_failure_receipt_cannot_be_read_through_state_link，当前 Windows 不允许创建该符号链接 fixture。不能将跳过记录当作 Windows 链接回归通过。

## 产品与交付边界

Git pre-commit 仍隐藏、默认关闭；没有修改 Codex 生命周期 Hook、MCP、Skill、任务结束检查、用户选择修复/忽略或复验。版本仍 0.3.3，优化分支未发布；没有动真实安装、系统配置或其他公司项目。源样本为用户自身项目固定提交，扫描器离线运行且不执行样本应用。

真实扫描验收只覆盖两个改动文件的 Python 与 JavaScript 静态范围。Python 由 Semgrep 检查，.mjs 由原有 native-js-function 对动态 Function/eval 作词法检查，Gitleaks 检查两个文件；FULL 是这些实际 provider 的请求范围契约，不表示全项目或所有 JavaScript 漏洞种类都已检查。完整项目为 660 个支持文件 / 4.35 MB，组件投影为 191 个 / 1.97 MB；不是两个独立真实项目，没有证明大型项目、Java、Go、TypeScript、依赖漏洞数据库或整体 Agent 体验。OSV 现有版本不符锁定要求。测量脚本主动提交 PARTIAL；模型 token 与推理耗时未测。

主任务需独立复核补丁和严格前后实测，完成完整 Demo/发布门槛；本任务没有推送、创建 PR/tag 或发布。收到放行后仍须等待 0.3.3 发布完成，再选择未占用的新版本号。当前局部优化结果不得作为完整产品验收放行的替代。
