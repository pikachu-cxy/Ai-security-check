# 本机 Codex 复测

安装完成后完全退出 Codex（⌘Q），再打开；已有 Codex CLI 进程也退出重开。
桌面与默认 Codex CLI 共用 ~/.codex，无需重复安装；自定义 CODEX_HOME 或另一台电脑除外。

## 1. 快速查看与完整核验

```sh
RUNTIME="$HOME/.local/share/AI-Security-Runtime-macos-trial/security-check"
CONFIG="$HOME/.config/ai-security-runtime/config.toml"
"$RUNTIME" runtime-info --fast --json
"$RUNTIME" integration status codex --scope global --fast --json
"$RUNTIME" development-config
# 仅需首次安装核验或排障时运行完整检查；耗时会比快速查询长。
"$RUNTIME" runtime-info --json
"$RUNTIME" integration status codex --scope global --json
```

快速查询应显示 NOT_REVALIDATED，不能把它视为扫描组件健康证明。
完整核验应标识实际新构建并核验安装内容。配置查询应为 VALID。

## 2. 容量限制与关闭

先备份配置，再用文本编辑器修改，避免追加重复 TOML 表：

```sh
BACKUP="$CONFIG.acceptance-backup.$(date +%Y%m%d-%H%M%S)"
cp "$CONFIG" "$BACKUP"
open -e "$CONFIG"
TEST_ROOT="$(mktemp -d "$HOME/Documents/security-config-acceptance.XXXXXX")"
mkdir "$TEST_ROOT/limits" "$TEST_ROOT/report" "$TEST_ROOT/rules"
printf 'value = 1\n' > "$TEST_ROOT/limits/a.py"
printf 'value = 2\n' > "$TEST_ROOT/limits/b.py"
printf '%s\n' "$TEST_ROOT"
```

将 `[scan.discovery] max_files` 改成 1，执行 development-config 确认。
在 Codex 打开 limits 文件夹，新聊天要求：“对这个项目做全项目静态扫描，不修改代码；报告实际范围和限制。”
预期是明确报告文件数限制，不声称全项目扫描成功。再将该字段改为 0，重新请求扫描，预期不再因这项限制拒绝。
其他输入/引擎限制仍独立生效；出现缺组件或过期库时如实报告，不计为此项容量开关失效。
容量调整影响新提交扫描；已提交后台任务沿用当时快照。

## 3. 自定义规则

在上面 rules 目录创建原生规则文件：

```sh
cat > "$TEST_ROOT/rules/demo.yaml" <<'YAML'
rules:
  - id: local.acceptance.eval
    languages: [python]
    message: Acceptance eval candidate
    severity: ERROR
    pattern: eval($X)
YAML
printf 'def parse(value):\n    return eval(value)\n' > "$TEST_ROOT/report/example.py"
printf '%s\n' "$TEST_ROOT/rules"
```

把 `[rules.sast]` 改成 `mode = "extend"`，paths 填入刚打印的 rules 绝对目录，exclude_ids 保持空列表。
在 Codex report 项目要求全项目扫描，不修改代码。预期可识别 `local.acceptance.eval` 候选；最终风险级别以
配置要求的 Agent 复核为准。把该完整 ID 加入 exclude_ids 后再扫，自定义候选应不再出现，其他规则仍可能命中。
故意填入不存在的规则 ID，应明确报错/覆盖缺口，不能声称自定义规则成功执行。
验完恢复 builtin、paths=[]、exclude_ids=[]。

## 4. Stop 报告、复核后重读与静态模式

每轮使用新聊天和实际新修改，避免将只读问答或旧结果当作新任务。
在 report 项目聊天要求：“给 example.py 增加一个接收字符串并交给 parse 的函数，不修复现有 eval；
完成后按产品流程报告本次修改的安全检查结果。”

观察会话工具记录：若 Stop 发生续接，最终风险应仍有标题/级别/来源/文件行链接及“问题、可能影响、建议修复、尚未确认”
四段，末尾给一次“修复／暂不处理”。提交复核成功后，应从 offset=0 重读风险并读完相关分页。
正常主动收尾成功时允许不触发 Stop；不要把“未出现 Stop”本身当作失败。

再将 `[agent]` 两项设为 false，保持 `[development.stop_fallback] enabled=true`。
新聊天实际编辑同一测试项目。预期仅报告静态候选，不提交 Agent 复核，不冒充 Agent 已确认；仍应提供处理选项。
只读询问“解释一下代码，不修改”，不应为了旧检查再次触发 Stop 续接。
Stop 次数和失败恢复仍按原有配置，不承诺每次最多一次。

## 5. 漏洞库

```sh
"$RUNTIME" vulnerability-data status --json
# 仅在要联网更新公开漏洞数据时执行：
"$RUNTIME" vulnerability-data update --json
```

update_mode=manual 时普通扫描不自动更新，显式 update 可更新；offline 时显式 update 也不得联网。
stale_policy=require_fresh 且库过期时，依赖漏洞扫描应报不可用/缺口，其他可执行静态检查可保留结果。
镜像配置只接受扫描器支持的公共 OCI 仓库；不支持任意 JSON/CSV 漏洞清单。

## 6. 恢复

```sh
cp "$BACKUP" "$CONFIG"
"$RUNTIME" development-config
```

这只恢复本次手工配置测试，不删除聊天、检查历史或源码。新开发批次读取恢复后的配置。
