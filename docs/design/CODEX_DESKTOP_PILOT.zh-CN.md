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

## 本机接入方式

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
