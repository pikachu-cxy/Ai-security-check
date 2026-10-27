# watchfiles 本机验收（2026-10-27）

本批按用户批准使用 watchfiles 1.3.0。先 Windows 原生桌面验收，通过后才提交 GitHub；再在 Mac 验收，不提前发布安装包。r01/r02 报告、原会话与已有故意漏洞样例均保留。本轮编号 r03，结果不混入之前的提速对照。

## 实现与边界

首次可能写入的原生 PreToolUse 注册当前工作区监听；begin 仍仅建元数据。监听在已有 MCP 进程的后台线程收集路径，原生文件补丁继续记录路径，Shell/Python 子进程由真实文件通知补充。收尾先排空通知并关闭监听，再沿现有入口合并扫描。普通聊天、只读调用不启动监听。没有 Git/status 补查、任务前文件内容清单或逐编辑扫描。

时间窗中的人工/其他进程修改也允许纳入，不证明具体写入者。旧脏文件本轮再次写入可见，未触碰的不据旧 Git 状态纳入。每 worktree 以实际目录及原 owner 隔离。排除现有默认忽略目录与运行时私有状态。每检查最多 1,000 条路径/64 KB 路径字节，进程最多 16 个活动窗口；30 分钟没有可能编辑的原生工具活动后过期。失败、丢失连接、慢启动、超限保留缺口。默认请求原生通知，未强制轮询；网络盘、容器和通知丢失的可靠性不能由本地磁盘结果推断。

动态新目录和目录整体搬移受原生通知语义约束。递归登记由库完成，开销随目录规模变化；忽略目录的事件筛选不等同于免去后端登记成本。不能承诺任何平台永不丢事件。后台子进程须在收尾前结束，收尾后的写入不纳入关闭的窗口。监听不提高静态规则/跨文件业务推理本身的覆盖能力。

实现依据：[watchfiles 后端](https://watchfiles.helpmanual.io/api/rust_backend/)、[Codex Hooks](https://learn.chatgpt.com/docs/hooks)。使用固定版本的同步注册后端，登记完成后才返回 Pre；没有逐平台自写监听器。

## 安装后先核对

开发环境命令（本机仓库根目录执行）：

```powershell
$py = 'C:\Users\24170\Desktop\AI-security-check\.venv\Scripts\python.exe'
& $py -m security_runtime.cli install codex --dev --offline --json
& $py -m security_runtime.cli runtime-info --json
```

本批交付时由开发聊天完成安装并记下结果，不要求重复安装。仅刷新设置中的 `ai_security_runtime` 连接；若 Codex 提示自有 Hook 定义更新，按正常宿主流程核对并信任。保持六个原聊天；不通过重启消除失败记录。配置写入不等于新连接或 Hook 已运行。

在验收聊天先要求只读查询真实 `get_runtime_info(view="summary")`，确认 `development_file_watch` 包含 `development-file-watch-v1`，再读同构建 core/development-check 指导。查询应不创建检查或扫描。没有能力时停止该组验收并报告仍加载旧服务，不猜测已启用。

## 六组原项目的 r03 提示词

沿用 `C:\Users\24170\Desktop\AI-security-acceptance-20261027` 下已建的六个项目及原聊天，模型 GPT-6.1 Terra、思考强度中。先在终端只读核对：

```powershell
$lab = 'C:\Users\24170\Desktop\AI-security-acceptance-20261027'
git -C "$lab\repository" worktree list
```

每组都粘贴下面公共提示词，将组名和文件清单替换为表内对应项。A 用原生补丁，B 用 Shell 启动的 Python 脚本写文件；两者是本轮采集方式对照，已经不沿用旧 A/B 等待秒数的含义。

| 组名 | 必须实际再次写入的文件（加上 `src/batch/view_00.js` 至 `view_09.js`） | 采集方式 |
| --- | --- | --- |
| code-A-r01 | `src/http/quote.js` | 原生补丁 |
| code-B-r01 | `src/http/quote.js` | Shell/Python |
| dependency-A-r01 | `package.json`、`package-lock.json`、`src/adapters/render.js` | 原生补丁 |
| dependency-B-r01 | 同上一行 | Shell/Python |
| business-A-r01 | `billing/routes.py`、`billing/service.py`、`billing/repository.py`、`billing/serializer.py` | 原生补丁 |
| business-B-r01 | 同上一行 | Shell/Python |

实际文件夹以 `git worktree list` 输出为准；不要因表内组名创建替代目录或重置原目录。

```text
这是 watchfiles Windows 原生验收 r03。当前组为【组名】，编辑方式为【采集方式】，必须写入文件为【表内清单加十个 batch 文件】。
模型使用 GPT-6.1 Terra、思考强度中。先核对当前实际目录/worktree 根，读取真实运行能力与同构建指导。

保留原 r01/r02 检查、失败和风险处置记录。本轮使用稳定 task_key=watchfiles-r03-组名 开始轻量元数据；如果本轮 Hook 已自动建立记录就沿用。不要新建全项目基线。
本轮只给上述文件增加无行为影响的验收注释：JS 用 // watchfiles-r03，Python 用 # watchfiles-r03；JSON 仅增加尾部空白。若标记已存在，在其后加一行 r03-retry 标记/空白，保证本轮实际写入。保留已有代码、依赖版本与离线样例行为，不引入新漏洞，不修复或升级依赖。
A 组使用原生补丁；B 组通过 Shell 启动 Python 脚本读写上述文件，不用原生补丁代写目标文件，等待子进程完成。不要伪造 Hook 或用 record_development_changes 人工补录。自动路径缺失就保留失败。
不执行动态代码、不安装项目依赖、不启动服务、不提交 Git、不读取项目外 oracle/别组答案、不改其他 worktree。

编辑期间不扫描；收尾前结束写入，再提交一次合并检查。若支持 complete_development_check 优先用它，否则 finish 一次后沿原引用读保存结果，不为等待重复 finish。
核对 file_watch、实际路径、dirty_seq/scanned_seq、扫描结果版本和全部 gaps；列出清单中漏采的文件，不能把零告警当作安全。
按实际源码分析本轮再次写入文件涉及的代码风险、依赖风险或跨文件租户权限链，保留必要关联分析；不要宣称风险一定是本轮新增，不保存排除/暂缓决定或申请修复。
最终给出：自动采集是否通过、风险识别证据、范围/组件缺口、完整回合耗时。检查/会话引用只在当前内部工具传递，不写项目或报告。报告保存为独立 r03 记录，不覆盖 r01/r02。
```

故意漏洞此前已在六组样例中存在，本轮通过再次写入覆盖它们来验证监听接入与风险识别衔接；这不是重新引入漏洞或验证“本轮新增风险归因”。业务组需要模型核对 routes → service → repository 的权限传递，静态零发现不能代替业务分析。

## 通过条件与负向检查

1. 六组全部实际编辑路径已自动记录，B 组不因命令语法未知而只剩空范围；A/B 各自的扫描结果包含代码/依赖/业务证据。删除、组件状态或原有历史缺口单列，不要求抹掉旧检查的 scope_unknown。
2. 一份检查的编辑阶段零扫描，收尾一次合并，最后保存结果序号匹配当前 dirty_seq。相邻 worktree 的专属修改不能出现在本组范围。无人工补录或手工构造 Hook。
3. 再做一个只读回合“读取 README 并解释，不编辑”：不启动新窗口/检查或扫描。
4. 可在测试任务开始前给一个额外文件作无害注释且不提交；本轮不再触碰该文件，它不得仅因 Git 脏状态被纳入。另一个旧脏文件在任务内再次写入，必须采到。时间窗内人工修改可被纳入，这是允许的规则。
5. 脚本的新增、删除、重命名、临时文件替换由下面隔离命令验证；原生桌面若再测这些操作，仅对新建无害临时样例操作。保留删除/短命临时文件的实际扫描限制，不把有路径等同于能扫描已删除内容。

可复现开发侧验证（不替代原生桌面）：

```powershell
Set-Location 'C:\Users\24170\Desktop\AI-security-check'
& $py -m pytest -q tests/test_development_file_watch.py tests/test_development_file_watch_hooks.py
& $py scripts/watchfiles_acceptance.py --output artifacts/watchfiles-windows-recheck.json
```

第二条在系统临时目录建立 6,000 文件、两个真实 Git linked worktree，完成后清理自己的临时目录。只运行无害写入脚本，不执行扫描器或漏洞样例。计时仅含注册/采集/排空与模拟提交，不能声称整体扫描提速。

Windows 验收结果由用户确认；确认通过后再提交当前源码、必要测试和进度到 GitHub。Mac 拉取同一提交、更新开发依赖并离线安装，再核对新能力及重复以上验收，另存 Mac 结果；没有实际 Mac 结果前状态保持待验收。
