# 在本机 Codex 体验实验版

这个入口用于在一个独立项目里体验：文件改完仍先做同步静态检查；完成一小段完整功能后，后台只读 Agent 分析该批改动；开发结束时，由主 Codex 核对最终代码并给出总结。

它只接管选定项目的 `ai_security_runtime` 连接。其他项目继续使用原版本。安装脚本不会改用户级 Codex 配置，不会替你信任 Hook，也不会仅凭配置文件就称运行成功。

## 用户怎么体验

本次本机体验约定使用桌面的 `AI-security-batch-demo` 文件夹；独立状态目录在本机 LocalAppData 的 `AI-Security-Runtime/experiments/batch-review-v1`。是否已经安装、真实 Hook 是否已经收到事件，以本轮最终交付和实际回执为准。

1. 在 Codex 中添加、打开桌面的 `AI-security-batch-demo` 项目，然后新开一个聊天。不要把它当成替换正式 Runtime 的安装包。
2. 若 Codex 询问是否信任这个本地项目，按正常界面确认。若提示 Hook 待审查，在 Hook 管理界面检查；CLI 对应 `/hooks`。已经信任、定义没有变化的全局 Hook 可继续复用。
3. 在这个项目里开一次普通开发任务。例如：“给订单接口增加按当前用户查询的汇总，并补上输入校验和测试。分几步完成，做好后给我总结。”不需要每次自己输入安全工具名。
4. 观察正常开发是否仍流畅、功能阶段之间能否继续工作、最后总结要额外等多久，以及风险提示是否准确、有帮助。短小的一处文字修改可能没有足够改动形成批次。

后台审查需要当前 Codex 登录可用，会消耗该账户的模型用量。默认每次开发任务最多派发两个中途审查；最终核对仍由主 Codex 完成。后台发现只是候选，改动已经修好或版本已经变化时，最终总结应按当前代码处理。

普通聊天不应启动任务或后台模型。项目配置已写入，不代表真实 Hook 已触发或安全审查已完成。应结合运行记录确认同步检查、后台派发、返回结果和最终核对确实发生。

## 2026-10-16 本机验收记录

桌面 `AI-security-batch-demo` 已完成项目安装，复用三类全局 Hook，新增 Hook 为零；全局配置、Hook 和公共 Skill 哈希保持不变。桌面项目保留初始功能，9 项标准库测试通过，可直接用于第一次体验；实际开发验收使用另一个隔离项目，未提前替你完成体验任务。

在已安装的 Codex `0.162.0-alpha.17.2` 中，使用同一套项目配置和现有登录完成了一次正常开发：主 Agent 自行实现状态筛选、分页、可选收据与测试，首次改动前基线与运行前清单一致，没有固定补丁重放。

- 两次真实文件编辑均触发同步静态扫描。最终任务静态检查 `COMPLETED/FULL`，覆盖三个实际改动源码/测试文件；Semgrep、Gitleaks 均成功，依赖和 IaC 检查在本次范围不适用。这不是全项目安全证明。
- 第一批检查点约在第 55.7 秒返回；主 Agent 在第 105.2 秒继续完成另一批文件编辑。后台模型实际读取绑定快照，约 71.2 秒完成；其历史结果被接受，但因文件后续修改，最终适用性为 `STALE`，没有复用成当前结论。
- 主 Agent 用最终版本证据提交集成核对，签名任务为 `COMPLETE`，版本仍匹配。最终覆盖保留 `PARTIAL`：测试文件部分上下文超出共享预算，且有脱敏语义未知。首次最终提交格式被拒，主 Agent 在同一会话内纠正后接受，没有重建基线或补扫清除失败。
- 原生开发回合约 214.3 秒；含进程启动和清理约 223.1 秒。生成后的 22 项业务测试全部通过，交付前独立重跑同样通过。
- 父回合输入/输出合计 618,067 token，后台回合 134,720 token；其中缓存输入已包含在输入、推理输出已包含在输出，不重复累加。后台模型为 `gpt-6.1-sol/high`。实际订阅账单未知；单次开发验收没有原流程配对，不能据此称提速或增质。

后台模型启动前的内部隔离正负探针全部通过，实际业务回调只有绑定读接口。探针使用本地无认证模拟路由验证宿主执行控制，不宣称看到了真实服务端的工具清单。后台用量是实际模型回执，独立于这些不消耗真实模型的探针。

这次验证了本机原生引擎与项目配置的正常开发链路，尚未代替你在桌面界面新聊天的体感体验。命令行验收仅在该进程中信任自建项目；没有写入私人信任库。桌面首次打开仍按界面审查项目信任。

接入、兼容性与关闭清理的各组针对性测试均通过。额外的本轮源码开发安全核查另有缺口：现有长驻连接返回静态 `FAILED/UNKNOWN`，未返回底层异常；共享上下文预算也已耗尽。该结果与上述独立冻结实验进程对示例项目成功执行静态检查分别保留，不能把流程验收通过说成本轮全部源码安全检查通过。

可复核的时间线、生成补丁、隔离摘要和用量见[验收证据](../evidence/codex-desktop-pilot-20261016/README.md)。此前三组配对比较及其样本限制仍见[真实模型比较](REAL_HOST_BATCH_PILOT.zh-CN.md)。

最新用户两批桌面体验另外暴露了预算预留不足：后台和静态运行成功，但最终审查会话未能建立。该失败没有被此前验收覆盖，现列为下一步 P0、待实现和复验，见[预算优化计划](BATCH_REVIEW_BUDGET_PLAN.zh-CN.md)。

## 安装命令

入口是 `scripts/codex_desktop_pilot.py`，项目安装器是 `scripts/install_codex_desktop_pilot.py`。以下均为 PowerShell 示例，将前三项替换为实际绝对路径，不需硬编码用户名称：

```powershell
$pilotPython = '<带依赖的 Python 绝对路径>'
$pilotRuntime = '<实验源码目录>'
$pilotCodex = '<本机 Codex 可执行文件绝对路径>'
$pilotProject = Join-Path ([Environment]::GetFolderPath('Desktop')) 'AI-security-batch-demo'
$pilotState = Join-Path $env:LOCALAPPDATA 'AI-Security-Runtime/experiments/batch-review-v1'
& $pilotPython -I "$pilotRuntime/scripts/install_codex_desktop_pilot.py" install `
  --workspace $pilotProject --state-dir $pilotState --runtime-root $pilotRuntime `
  --python $pilotPython --codex $pilotCodex
```

项目配置通过同名 `mcp_servers.ai_security_runtime` 覆盖该项目的连接，显式设置 `SECURITY_RUNTIME_GLOBAL=0`，避免继承用户级连接的全局路由。启动器由 `python -I` 运行固定脚本，使用实验源码，不依赖原虚拟环境 editable 安装指向哪里。模型后端仍使用 Codex 现有登录，不复制、打印或改写认证文件。

安装前会检查用户级和项目级 Hook。已有的原生 `SessionStart`、同步 `PostToolUse`、`Stop` 三组可复用，缺少哪组才补到项目 `.codex/hooks.json`；重复或不匹配的 Runtime Hook 会拒绝安装并提示人工核查。Hook 的执行定义与信任记录分开：安装器不编辑 `hooks.state` 或任何信任库。官方说明多个层级的 Hook 会一起加载，不会按配置优先级自动替换，因此不能简单再安装完整的一套。[官方 Hook 文档](https://learn.chatgpt.com/docs/hooks)

项目级配置和 Hook 需要项目受信任后才会加载；新 Hook 还要信任当前定义。[官方配置说明](https://learn.chatgpt.com/docs/config-file/config-advanced)

后台只读模型由实验连接的可信宿主调度器启动，不使用开发 Agent 的继承工具。开发 Agent 按项目 `AGENTS.md` 在有意义的阶段发出批次检查点，继续开发，结束时走既有 `finish`、`prepare`、读取证据、提交最终审查流程；不能仅靠暴露批次工具就称已自动运行。

## 查看状态与停用

同一组路径下，将命令的 `install` 改成 `status` 可查看配置状态，改成 `remove` 可恢复安装前文件。两者不需要 `--python`、`--codex`。

```powershell
& $pilotPython -I "$pilotRuntime/scripts/install_codex_desktop_pilot.py" status `
  --workspace $pilotProject --state-dir $pilotState --runtime-root $pilotRuntime

& $pilotPython -I "$pilotRuntime/scripts/install_codex_desktop_pilot.py" remove `
  --workspace $pilotProject --state-dir $pilotState --runtime-root $pilotRuntime
```

停用后关闭并重新打开该项目的 Codex 聊天，使 MCP 重新连接。其他项目原连接始终不受影响。

`status` 将配置和连接报告分开：`INSTALLED_NOT_OBSERVED` 表示安装器还没有可用的回调记录；`INSTALLED_CALLBACK_REPORTED` 表示实验 Runtime 在该项目报告收到过初始化回调。这些记录不是安全通过，也不能单独证明回调由桌面自动触发。真实体验验收还需核对宿主事件和模型记录。

安装器只管理 `.codex/config.toml`、`.codex/hooks.json` 和追加了实验指导的 `AGENTS.md`；安装前的完整字节备份及哈希保存在项目外的安装回执里。若安装后手动修改了其中任何文件，自动回退会停止，避免覆盖你的新内容；保留回执，核对差异后再处理。状态目录应放在源码仓库和认证目录之外，不要提交到 GitHub。

## 验收边界

配置安装验收与真实体验验收分别记录：

- 安装器测试只证明同名覆盖、Hook 复用、路径边界和回退，不证明桌面事件或模型审查已经发生。
- 一次真实开发应记录同步静态检查、批次的启动/完成/失败、实际模型用量、最终版本核对，以及遗漏范围。
- 子 Agent 失败或隔离证明失效时保留主 Codex 的最终审查，并说明中途覆盖缺口；不能把失败改写成“安全检查通过”。
- 现有小样本真实模型比较没有证明短任务一定更快。此次本机体验用于观察真实开发节奏下的等待和提示质量。
