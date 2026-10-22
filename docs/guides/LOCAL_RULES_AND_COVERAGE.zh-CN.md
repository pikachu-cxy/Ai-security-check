# 内置规则与本地规则

当前源码保留简单的规则交付方式：默认使用仓库自带的 `ai-security-core`，用户可以自行维护本地 Semgrep YAML 规则目录。没有新增在线更新服务、签名信任库或自动版本切换。

```powershell
security-check scan --path C:\projects\my-app --rules C:\security\my-rules
```

`--rules` **替换**本次扫描的默认 Semgrep YAML 规则集，不自动合并。需要保留默认规则时，将 `src/security_runtime/rules` 复制到自己的目录，再添加或修改 YAML；升级时自行同步该目录。规则文件变化会改变扫描所绑定的规则校验值。不要把本地规则目录放到待扫描源码中。此选项不替换独立的原生数据流扫描器；其语言解析模型属于程序代码。

最小本地规则示例：

```yaml
rules:
  - id: company.php.forbidden-debug
    languages: [php]
    severity: WARNING
    message: Remove debug_dump before deployment.
    pattern: debug_dump(...)
```

## 本次补充范围

规则包 `1.4.0` 新增 12 条默认规则；当前 `1.6.0` 为 71 条独立规则、63 条默认启用，其中 Python 为 18 条。JS/TS 共用规则只计算一次。

| 范围 | 新增 | 已建模的调用与边界 |
| --- | --- | --- |
| Go | 4 | `*http.Request` 处理函数中的 Query/FormValue/PostFormValue 到 `exec.Command("sh"/"bash", "-c", ...)`、`os/ioutil.ReadFile`、`http.Get/Post`；`tls.Config.InsecureSkipVerify: true` |
| PHP | 6 | GET/POST/REQUEST/COOKIE 输入到 system/exec/shell_exec/passthru、mysqli_query、eval、单参数 unserialize、include/require、echo |
| JS/TS | 2 | HTTPS 模块的 request/get/Agent 显式关闭证书校验；location.hash/search 到 innerHTML/outerHTML/document.write |

这些 YAML 规则是部分 API 模型：Go 不包含 Gin/Echo 框架、任意 Client 方法或跨文件包装函数；PHP 不包含所有 PDO/ORM、框架输入或多参数 unserialize 选项；JS/TS 不包含所有网络库、消息事件、模板和 HTML sanitizer。TLS 自定义验证回调需人工确认。PHP HTML 编码只对应 HTML 文本语境，不证明脚本、属性或 URL 语境安全。

另外，feature/release 扫描启用独立的 `ai-security-go-sql 1.0.0`，仅补齐同包直接调用/已确定类型方法的 Go SQL 跨文件链路，最多两条调用边。只读已捕获的目标和上下文，限 64 文件、2 MB、100000 步及 3 秒软预算，超限保留部分覆盖。quick 不启用，不支持接口分派、反射、任意跨包分析或完整 Go 语法。

内置 Python 命令/eval/exec/SQL 告警使用有界本地证明过滤，最多每文件 0.2 秒、一次扫描 1 秒软预算。`1.4.2` 识别函数内新建 ConfigParser 的固定选项（外部读取、插值、别名修改和不明确取值均不放行）；eval/exec 还识别首尾引号、无内部同类引号且校验失败立即退出的精确防护。该防护不适用于命令执行、重新赋值或后续拼接。模型假定标准字符串及 ConfigParser 语义，不覆盖运行时替换和自定义字符串子类；没有增加跨函数或跨文件分析。无法建立模型内证明时保留告警，诊断分别记录常量和字面量防护依据。SQL 字典传播保留危险值经过其他键写入后的污点；安全键、固定覆盖值、字典 get 及常量缺省值由本地常量模型区分，参数绑定不视为 SQL 文本拼接。用户通过 `--rules` 指定的规则不使用这层内置过滤。PHP 仅识别精确的四段数值检查及重建，不把一般的 `is_numeric` 或转义函数当成万能防护。

Vue SFC 现已提取顶层 script / script setup 的 JS/TS，并保持原始行列及 UTF-8 偏移。模板、样式、外链脚本和双脚本之间的数据流未覆盖，Vue 整体最多部分覆盖。每文件 512 KiB、每次 64 文件 / 4 MiB 投影输入；规则包含路径 include/exclude 时暂不投影 Vue，并记录原因，防止临时路径改变用户规则范围。规则被安装或选中不等于本次已执行；只有引擎的实际规则与文件证据才计入执行覆盖。

`1.6.0` 新增 Flask 路由直接返回格式化字符串的 XSS 模型；部分 split 与 base64 编解码可传播，但未知帮助函数、间接响应和任意格式容器仍有缺口。JSON / 字典、显式纯文本、模板及已建模转义单独作为负例验证。原有显式 shell 模型新增一类相邻列表 append/pop/index 取值；不推广为任意容器分析。内置常量过滤进一步检查完整路径及格式化响应操作数，仍沿用上述软预算。未知导入路径前缀不会仅因叶子文件名固定而放行。

原生有界数据流保持 `1.5.0` 及原有范围：文件内 `pathlib.Path.read_text/read_bytes` 仍属于实验模型，默认 Python 路径检测限于已解析跨文件调用或精确的 `io.open/codecs.open`。后续须先补路径部件替换、绝对后段覆盖前段的精确语义与安全负例，再评估默认推广。不增加跨文件范围或扫描预算，不启用全部实验性命令 / 路径模型。`--rules` 不替换这些原生能力；用户规则也不会被内置 Python 常量过滤器悄悄改写。

## 如何验证规则变更

每条内置规则在 `tests/rules` 中有 `ruleid:` 正例和 `ok:` 反例，目录由 `catalog.json` 关联。JS/TS 新规则分别执行两种扩展名的用例。

```powershell
python scripts/test_rules.py --lint-only
python scripts/test_rules.py
```

完整验证使用项目固定的 Semgrep 版本，核对规则加载和所有预期命中位置，并拒绝反例或其他位置的意外告警。合成正反例通过只能证明这些样本，不代表真实项目准确率；上线前仍需在自己的项目上验证误报和漏报。

固定项目验收由 `tests/benchmarks/rule_acceptance.json` 记录项目版本、文件哈希与标签，`rule_acceptance_expected.json` 保存已有命中基线。准备好清单中的本地项目后，可从仓库根目录执行：

```powershell
$env:PYTHONPATH = (Join-Path (Get-Location) 'src')
python scripts/run_rule_acceptance.py --project benchmark-python --repeat 1 --output-dir .tools/acceptance-python-new
python scripts/run_rule_acceptance.py --repeat 5 --output-dir .tools/acceptance-all-new
```

输出目录必须尚不存在；脚本只做静态分析，不下载、安装或启动基准应用。它分别比较 Semgrep 与默认原生分析合并后的真阳性 / 误报，检查输入和扫描源码是否变化；不能拿原始 YAML 候选数替代产品结果。耗时比较应使用相同项目、工具、批量设置及静止源码，在无其他重负载时分别运行至少五次；固定样本通过不代表真实项目总体准确率。

`1.5.0` 新增 Python 显式 shell 命令槽、JS/TS 请求输入到 eval / Function / vm 的污点规则，并补充显式 Express Request 的部分来源。局部传播、拼接和安全覆盖使用现有 Semgrep 分析；没有新增跨文件图。规则模式及引擎实际返回的路径证据分别记录，未返回路径时不会自动编造调用链。可运行 `python scripts/test_javascript_rule_product.py` 和 `python scripts/test_vue_rule_product.py` 复验产品路径。

Vue 的本次支持用于发现脚本候选；内置和本地 SAST 规则的零发现暂不作为自动确认修复的依据，复查保留不确定状态。完整模板/脚本组合语义尚未建立。
