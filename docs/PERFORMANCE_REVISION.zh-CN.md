# 独立复核 revise 后补验

本轮没有再改生产优化实现，原分页实测 JSON 未修改，没有重跑或泛化提速比例；只修正报告判定并补测试/真实引擎正例。不推送、不发布。

## 报告判定修正

旧 summarize_task_measurements.py 在标题写死“通过/28%/30%/不重叠”，独立复核指出这不能用于判定。本轮删除固定结论，由真实数据计算中位变化和范围，且先验证：两种规模各至少三个不同任务重复，每次三个上下文页，各阶段计时为正且有限；Hook、静态 provider、任务结束和结果状态成功；原扫描覆盖完整适用范围，所有请求文件进入实际范围；签名快照、内容、发现、规则环境和覆盖一致。Runtime 加入额外 manifest 上下文时可接受实际范围为请求范围的超集，额外范围仍必须在前后一致，不允许缺失请求文件。

两规模分页中位耗时都下降，且各自前后范围不重叠才宣布本地阶段通过。等速/变慢、变化小于观察波动、不足轮次、重复任务、失败/不完整执行、Hook 失败、陈旧结果、身份不同、非有限计时及缺页都不能通过。错误输入覆盖旧输出时写入“验收未通过”，避免留下旧的通过报告。

定向回归 26 passed，13.96 秒（revision-final.xml）。其中七项为 freshness 场景；十九项报告判定测试包括人为构造的 40% 收益必须输出 40% 而非旧 28%/30%、等速与变慢、范围重叠、各种失败、错误 CLI 覆盖旧通过报告。原 107 passed/1 skipped 回执仍保留，不将两次测试数字相加伪装成一次完整回归。

用原严格实测重新生成报告：component 27.9616657%、full 29.8570572% 的局部分页耗时下降；数据与判定门槛未放宽。不是整轮审计、模型或 token 提升。

## 五秒预算边缘

新增 test_faster_hash_path_at_five_second_budget_is_conservatively_stale：实际读取同一组文件，只有时钟和脱敏成本被控制。完整文本路径在 5 秒预算边缘取得 2 个哈希并保留 INVENTORY_READ_BUDGET；不生成未用文本的路径取得 3 个哈希。内容没有修改，_fresh 仍返回 False，不将更完整新快照用于旧证据复用。未取消预算或末次读取，也未依赖 mtime/TTL。

## 真实扫描引擎正例

项目仍为用户自身 pikachu-cxy/Ai-security-check，固定 755e411，样本仍为组件投影。两版分别在新的隔离副本中，对现有 task_security.py 追加明确标记 ARTIFICIALLY INJECTED ACCEPTANCE FIXTURE 的函数，使用 yaml.unsafe_load(payload)。这是人工注入，不是宣称原项目含此漏洞；函数从未执行。

两版实际 task finish 均由 Semgrep 1.178.0 检出一项 ai-security.python.unsafe-yaml。TaskFixService.prepare 仍明确 user_consent_required=True，没有把准备当成授权。脚本先保存明确“修复”选择，再仅把注入函数改成 yaml.safe_load。该选择的信任标签为 HOST_REPORTED_CONTROLLED_SCENARIO_CHOICE，授权来自本次明确委派的受控注入/修复验收请求；它不是用户在真实桌面点选，也没有授权真实安装或项目改动。

随后用原 TaskFixService.verify 和同一真实 originating Semgrep engine 复验，两版均 SCANNER_VERIFIED_RESOLVED，scanner_recheck=True、engine_process_observed=True；host 报告的 patch_applied 与 Runtime 自己观察的扫描事实分开。再次任务 finish 两版均 COMPLETED/FULL、发现 0。起始/风险/修复快照哈希、末次文件哈希、发现位置/规则/规则内容校验和、provider 版本/状态和适用范围已自动比对一致，controlled-risk-comparison.json 为 PASS。

原始记录位于隔离工作区外层 controlled-risk-before.json、controlled-risk-after.json；controlled-risk-before/after 保存副本及状态。测试仅调用 Runtime/已安装扫描器，离线、不安装依赖、不执行注入/修复后的样本代码、不读取公司其他业务仓库。

此正例证明有限范围的“检出→明确受控选择→修复→原引擎复验”没有被本地优化破坏。零发现、人工注入以及未运行模型的 PARTIAL 都不是完整安全验收。SCA、真实 Java/TypeScript 和 Codex 桌面体验仍未测；未扩展 Go，未改变 OSV 版本。继续待主任务独立复核，不推送发布。
