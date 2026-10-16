# Codex 托管 worktree 准入修复

仅修改 `codex/batch-security-review-v1` 实验分支，不替换现有安装或全局接入配置。

## 原因和改动

旧规则将整个 Codex home 及子目录视为内部状态目录，连合法的
`CODEX_HOME/worktrees/<id>/<repo>` 也被拒绝。普通任务开始接口又把具体原因压成
通用的“工作区或引用未接受”，用户无法分辨目录拒绝和代码检查结果。

现在仅为经过校验的 Git linked worktree 开放例外：

- 严格匹配上述托管布局，候选可以是该仓库的源码子目录。
- `.git` 必须是有界单行指针，管理目录必须属于外部 Git common-dir 的 `worktrees`。
- 管理目录的 `commondir` 和指回当前 `.git` 的 `gitdir` 必须形成双向绑定，且有必要的
  HEAD、配置和对象目录。所有相关路径检查符号链接及 Windows junction。
- common-dir、管理目录、项目根均不能命中 Runtime 状态或显式排除边界；Git 最终解析
  的根必须与校验过的托管根一致。嵌套仓库、伪造指针和普通 `git init` 不获得例外。
- 默认与自定义 Codex home 仍受保护，Cursor 的内部目录沿用原来的拒绝策略。

全局路由、项目配置层检查和只读诊断使用同一准入规则，避免第一层通过后被第二层再次
拒绝。普通工具现在保留固定的失败原因与阶段，并给出对应中文提示，不返回任意异常、
路径或任务参数；子工具的引用错误仍按子工具失败处理。

## 实际验证

使用独立的实验 MCP stdio 进程，读取当前真实接入配置，并访问真实托管 worktree：

- 成功开始任务，建立 **725 个文件**的基线。
- 无源码改动，以 `NO_CHANGES` 收尾，没有执行静态扫描或调用模型。
- 对 Codex home 本身的任务请求仍被拒绝，回执明确为目录边界问题，保留失败阶段。
- 验证前后全局 `config.toml`、`hooks.json` 和托管 worktree 的 `.git` 字节 hash 相同。

这是一项独立无改动验收任务，不作为之前开发修改的安全检查基线。
回执：`artifacts/worktree-admission-smoke-20261016/receipt.json`；重跑入口：
`scripts/verify_worktree_admission.py --workspace <托管仓库绝对路径> --output <新目录>`。
必须通过进程内 `PYTHONPATH` 绑定实验版 `src`，不修改全局配置。
输出目录须在被测仓库之外，因为验收进程把任务状态放在输出目录中；项目内部状态
边界仍会拒绝这种布局。已提交的托管实验版随后也以自身源码再次通过相同 stdio 验收，
建立 728 个文件的基线并正常无改动结束；记录为
`artifacts/worktree-admission-managed-final-outside-20261016/receipt.json`。

真实 Git 边界回归已覆盖合法项目及子目录、伪造/损坏元数据、状态目录、明确排除、
嵌套仓库、环境覆盖和链接，Windows 文件符号链接 fixture 的权限限制单独保留。

相关测试的最终逐项结果为 **215 项通过、4 项跳过**：

- 准入边界：42 通过、3 跳过；跳过的文件符号链接 fixture 缺少 Windows 创建权限，
  实际目录 junction 的拒绝测试通过。
- 错误诊断、全局绑定、任务传输和 Hook 反馈：108 个不同节点最终通过。合集初次
  一项在源码并发编辑时出现构建身份漂移，源码稳定后该节点复跑通过；新增的托管任务
  流程与 Cursor 边界各单独验证通过，没有以忽略断言处理失败。
- 全局接入回归：65 通过、1 跳过，跳过原有系统链接 fixture；有一项依赖库的
  settings 类型定义警告。JUnit 为 `artifacts/worktree-global-integration-tests.xml`。

本轮开发修改另有编辑前基线和完整任务范围静态检查：6 个改动文件，代码与秘密检查
均执行成功，零发现；依赖清单未改动，不宣称执行了完整依赖图检查。上下文核查已提交，
但两文件的改动前文本未被预算缓存，64KB 读取额度也未覆盖部分测试和关联代码，
因此保留部分覆盖，不将零发现称为完整安全审计。记录为
`artifacts/worktree-fix-security.json`。初始化阶段的旧失败提示不再代表本轮任务状态。

## 后续宿主验证

修复目录问题后已重跑宿主完整工具清单预检：当前宿主仍包含通用执行包装及
`collaboration.*` 工具，未满足只读审查者的完整清单要求。这与本次目录准入缺陷独立。
没有启动模型，实际耗时、发现质量和模型成本仍未测量。
新记录：`artifacts/real-host-after-worktree-fix-20261016/comparison.md`。

当前全局连接继续使用原安装；修复通过单独实验连接验证，不宣称原连接已热更新。
