# 第 6 轮规则优化：Java、Python、JS/TS 与官方规则对照

日期：2026-10-16。本轮按用户要求直接在本地默认分支 `feature/runtime-mvp` 开发，起点为 `33b6f408659a1bca0a889eebb04327c862cd2fbd`。修改产品规则、分析器、测试和评估脚本；被测项目业务代码及上游标签保持不变。本轮尚未提交、推送、构建安装包或更新全局接入。

## 采用的改动

- Java JDBC：区分 `Statement.addBatch` 的队列与实际 `executeBatch` / `executeLargeBatch`；在已解析的跨文件调用间保留同一个 Statement 的队列。仅排队、清空后执行、常量 SQL、PreparedStatement 绑定值均有负例。最多保留 32 次追加，超出范围记录分析缺口。
- Java 路径：默认启用已解析的跨文件路径流。其他 Java 单文件路径模型仍为实验范围，没有批量启用原有 8 条默认关闭规则。
- Python：保留有类型依据的字符串 `split` / `rsplit` 传播，补充 Flask `full_path` / `url`，以及显式动态 `route` 上下文中的 `path`。固定路由不作为动态 path 输入，上下文随已解析 helper 传递并在返回时恢复。动态路由的字符串片段仍采用保守污点传播；未建模的注册方式、SDK 和动态调用保持未知，不能据此证明路径安全。
- Python 新增窄规则：规范化根目录的文件查找中，把 `commonprefix` 当作目录边界并继续 `stat`。只覆盖有上下文约束的这种模式，未声称覆盖所有错误路径校验；同名公共前缀、无文件操作、错误比较对象和 `commonpath` 有反例。[Python 官方文档](https://docs.python.org/3/library/os.path.html#os.path.commonprefix)说明该 API 按字符比较。
- JS/TS SSRF：补充有 Express `Request` 导入依据的类型化处理器，以及有 `request` 模块导入依据的 HTTP 方法地址参数。不按函数名猜测客户端，没有新增 JS 全程序跨文件分析。
- 评估：增加无完整标签项目的固定文件清单；有上游标签的基准禁止覆盖该清单。官方对照增加所选 CWE 类别和 JS/TS 语言，跨语言规则 ID 去重，并核对实际扫描文件与执行规则。

核心规则包 `1.3.2`：56 个规则身份，默认 48 个；Java 34 / 默认 26，Python 16 / 默认 16，JS/TS 共享 6 / 默认 6。独立有界数据流包 `1.4.0`：6 个身份、默认 4 个。SDK 分支不额外计作规则身份。应用源码版本仍为 `0.3.4`。

## 固定基准的前后结果

Java 使用 OWASP BenchmarkJava 固定提交 `b06d6efaebd577a327514364951916e7df3290b4`，SQL 504 例、路径 268 例。Python 使用 [OWASP BenchmarkPython](https://github.com/OWASP-Benchmark/BenchmarkPython) `0.1`，提交 `f1291485808b66e20ddb6b01b10dc71b3df8c8ba`，本次选取七类共 428 例。类别范围不是整个上游基准。

每次扫描均核对文件哈希、上游 CSV、规则身份与执行回执；最终各类别 UNCERTAIN 均为 0。下表单位为“上游文件及漏洞类别”，不是告警数量或生产准确率。

| 范围 | 阳性 / 阴性 | TP 前→后 | FP 前→后 | FN 前→后 | 召回率前→后 |
| --- | ---: | ---: | ---: | ---: | ---: |
| Java SQL | 272 / 232 | 196→203 | 10→10 | 76→69 | 72.1%→74.6% |
| Java 路径 | 133 / 135 | 11→15 | 12→12 | 122→118 | 8.3%→11.3% |
| Python 路径 | 65 / 103 | 20→20 | 6→6 | 45→45 | 30.8%→30.8% |
| Python SQL | 5 / 11 | 5→5 | 0→0 | 0→0 | 100%→100% |
| Python 命令 | 13 / 7 | 7→7 | 7→7 | 6→6 | 53.8%→53.8% |
| Python 代码注入 | 20 / 33 | 10→10 | 16→16 | 10→10 | 50.0%→50.0% |
| Python 反序列化 | 18 / 36 | 7→7 | 5→5 | 11→11 | 38.9%→38.9% |
| Python XSS | 31 / 58 | 0→0 | 0→0 | 31→31 | 0%→0% |
| Python XXE | 8 / 20 | 0→0 | 0→0 | 8→8 | 0%→0% |

本轮减少 11 个 Java 漏报；逐案例前后比较无新增 FP，也无原有 TP 丢失。Python 基准没有提升，不能把真实项目新增告警换算到该基准召回率。原有误报仍存在。

沿用历史 case-ID 哈希分组，Java SQL 开发组 TP 163→169、FP 8→8，历史回归组 TP 33→34、FP 2→2；Java 路径开发组 TP 6→9、FP 10→10，历史回归组 TP 5→6、FP 2→2。Python 两组均未变化。这些样本已被历史迭代使用，模板独立性未建立，不是新盲测。

## 拒绝的候选

第一次把所有 `request.path` 片段都当输入，Python 路径 TP 仍为 20，FP 从 6 增至 9，拒绝。对应三例是固定路由的固定路径段；补充动态路由上下文、跨文件 helper、上下文恢复和固定路由反例后，最终重跑恢复 FP 6。没有修改上游标签、删除失败案例，或把 `startswith`、`'../'` 检查当作通用安全证明。

## Semgrep 官方规则的同范围对照

固定官方 `p/default` 下载快照 SHA256：`f028d6b0eaa186ae43fec92e5fdac22c03ed41ddd4dca359c54cf6a262de5492`，共返回 1074 条规则，另有未取得规则字段，不计作已测试。该快照不是本轮重新获取的“最新官方全集”。两边使用本机相同的 Semgrep CE `1.178.0`；不包含付费引擎或其跨文件能力。

按语言和所选类别声明的 CWE 自动选择全部对应规则，Java 17 条、Python 103 条、JS/TS 共享 88 条；Java 本轮只比较 SQL / 路径，其余语言比较七类及 SSRF 的适用子集。没有按效果挑规则。官方规则、许可与配置留在本地忽略目录，仅作对照，没有进入内置规则或分发包。

下表每格为 TP / FP，分母与前表相同；“产品”包含第一方静态规则及独立数据流分析，不能据此声称 YAML 本身更强。

| 范围 | 产品优化前 | 产品优化后 | 官方快照，CE |
| --- | ---: | ---: | ---: |
| Java SQL | 196 / 10 | 203 / 10 | 253 / 170 |
| Java 路径 | 11 / 12 | 15 / 12 | 120 / 106 |
| Python 路径 | 20 / 6 | 20 / 6 | 2 / 2 |
| Python SQL | 5 / 0 | 5 / 0 | 5 / 0 |
| Python 命令 | 7 / 7 | 7 / 7 | 7 / 7 |
| Python 代码注入 | 10 / 16 | 10 / 16 | 20 / 33 |
| Python 反序列化 | 7 / 5 | 7 / 5 | 18 / 12 |
| Python XSS | 0 / 0 | 0 / 0 | 0 / 16 |
| Python XXE | 0 / 0 | 0 / 0 | 0 / 0 |

官方的 Java 召回率较高：SQL 93.0%、路径 90.2%，同时在本组产生大量 FP。产品最终 Java SQL 精确率 95.3%、路径 55.6%，官方分别 59.8%、53.1%。Python 路径产品召回率较高，但绝对 FP 6 也高于官方的 2。Python 代码注入和反序列化的覆盖缺口仍明显，不宜简单整体替换或整体宣称优于官方。

## 新增已知漏洞版本与修复版本

仅下载和扫描源码，不安装目标依赖、不构建或运行目标应用。提交身份及文件哈希保存在本地回执。

| 项目 | 已知问题版本→修复版本 | 实际源码范围 / 每版 | 原问题检出：产品前→后 / 官方 |
| --- | --- | ---: | --- |
| Spark Java | 2.7.1→2.7.2 | `src/main/java` 99 文件 | 漏报→漏报 / 漏报 |
| Starlette | 0.26.1→0.27.0 | `starlette` 34 文件 | 漏报→检出 / 漏报 |
| send | 0.8.3→0.8.4 | `index.js` 及 `lib` 3 文件 | 漏报→漏报 / 漏报 |

三个修复版本在原通告的对应目标范围均无命中；这只作为原问题的负对照，不证明整个修复版没有其他漏洞或全项目误报率为零。官方 Starlette 两版都有一处模板相关告警，位于其他文件，未算作目录边界漏洞的检出或修复版误报。

通告与修复依据：[Spark CVE-2018-9159](https://github.com/advisories/GHSA-76qr-mmh8-cp8f)、[Starlette GHSA-v5gw-mw7f-84px](https://github.com/Kludex/starlette/security/advisories/GHSA-v5gw-mw7f-84px)、[send CVE-2014-6394](https://github.com/advisories/GHSA-xwg4-93c6-3h42)。Starlette 用于本轮规则开发，不是独立盲测成功证明。

源码提交：Spark `5316c0d0f057daaf556c3907c20df975f7bf8a8a` / `030e9d00125cbd1ad759668f85488aba1019c668`；Starlette `8965f8849977b5752e415722a83aa00049f80ff3` / `0c4b68ac4e179a788e38bac28f299dcad0f36e99`；send `463d1c92267d0b84e5df27f2aecad62859d5a57b` / `c00b287725234439237b0f70b94475ccd55e58f2`。

## JS/TS 教学项目观察

[OWASP Juice Shop](https://github.com/juice-shop/juice-shop/tree/v17.1.1) 固定 `v17.1.1`、提交 `39b46860612990ae18d499a20472172839fe8c77`，仅选应用后端 `routes` / `lib` / `models` 和顶层 `data/*.ts`，111 文件；NodeGoat 本轮固定后端 JS 范围 24 文件。两个项目均无用于本次完整计分的官方逐文件真值，不能公布语言整体召回率或把未复核告警计为误报。

| 选定源码位置 | 产品前→后 | 官方快照 |
| --- | --- | --- |
| Juice Shop 头像 URL SSRF | 漏报→检出 | 检出 |
| Juice Shop captcha / userProfile 代码注入，两处 | 均检出→检出 | 均检出 |
| Juice Shop login / search 原始 SQL 拼接，两处 | 均漏报→漏报 | 均检出 |
| NodeGoat research SSRF | 检出→检出 | 漏报 |
| NodeGoat contributions eval，一个文件三处调用 | 检出→检出 | 检出 |

官方在 Juice Shop 的其余路径等告警尚未逐个定性，原始告警数 29 不等于 29 个已确认漏洞。NodeGoat 官方 6 条告警来自同一文件的三处调用，按本表计一个选定位置；产品独立 JS 词法检查的三条结果也保留，未因它们与静态扫描分开存储而遗漏。

范围纠正的原始试跑保留：Juice Shop 最初 196 文件含 `data/static/codefixes` 教学片段，官方产生 26 个解析错误，整体为 PARTIAL，不能作为完整比较。新 111 文件范围按整个教学目录排除规则确定，三方重跑完整；不是逐个剔除失败文件。send 最初只选中入口转发文件，未覆盖 `lib/send.js`，该试跑不计作已测原漏洞；补齐全部生产 JS 后三方重跑完整。

## 验证与等待成本

- 核心 56 条规则的正反例门槛通过：186 个危险命中、159 个安全对照。它们是合成规则测试，不是生产准确率。
- 相关产品回归最终为 310 项通过、6 个 subtest 通过，14.02 秒。首次临时目录环境失败、旧数量断言失败及修复前回执均保留；上述数量指最终定向测试，不是全仓测试。
- Java 772 文件、Python 428 文件分别以产品原生入口单次调用复核，全部 SUCCESS，发现集合与评估器逐批执行一致，均未触发 30 秒停止启动后续批次的限制。
- 原生入口本地单次观测：Java 20.078→21.000 秒，Python 2.031→2.203 秒。约增加 0.92 / 0.17 秒；不是统计显著的性能估计，也不是每次开发或模型、Hook 的等待。日常 quick / 文件编辑 Hook 没有加入本轮有界分析器；新静态规则仍可能有少量开销，尚无真实宿主时延验收。
- 评估器每进程使用 2 个 Semgrep worker，设置与日志均限于回执目录。没有改全局设置或重新安装 Runtime。

以上规则测试和基准记录不能替代开发任务自身的自动安全核查，也不能声明未发现的风险已被排除。

## 证据与复现

完整本地证据：`artifacts/rule-dataflow-20261016-r6/`（Git 忽略），包括 `source-before.json`、`source-after.json`、`corpora-lock.json`、`projects-final.json`、逐批源码/规则哈希、原始结果、`java-comparison.json` / `python-comparison.json`、两组历史划分比较、`scoped-case-results.json`、最终 JUnit 与单次原生回执。被拒绝候选 `*-after` 与最终 `*-accepted` 分开，前者不替代最终结果。

核心包 SHA256 `335a2474ba60ba7b7c22b819417b5e5e44e8e022d372c34bf0075f36e4df9214`；有界分析包 SHA256 `0c189e1b327c079d9cab26f05ed6c9f862dd3c78d5a6f5074a5206de274d71ee`。优化前源码的 301 文件快照留在 `.tools/rule-quality-20261016/r6/baseline/`，与当前源码分别通过进程内 PYTHONPATH 执行，不替换全局安装。

已有本地引擎环境中，在仓库根目录复测，使用新的输出目录：

```powershell
$env:PYTHONPATH = (Join-Path (Get-Location).Path 'src')
$env:SECURITY_RUNTIME_OFFLINE = '1'
$runRoot = Join-Path 'artifacts' ('rule-retest-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))

.\.venv\Scripts\python.exe scripts/rule_quality_evaluation.py `
  --root '.tools/rule-quality-20261016/corpora/BenchmarkPython' `
  --kind python --split all --groups sqli pathtraver cmdi codeinj deserialization xss xxe `
  --dataflow --jobs 2 --output "$runRoot/python"

.\.venv\Scripts\python.exe scripts/compare_official_semgrep.py `
  --registry-file '.tools/rule-quality-20261016/semgrep-default-r4.yml' `
  --baseline "$runRoot/python" --groups sqli pathtraver cmdi codeinj deserialization xss xxe `
  --executable '.venv/Scripts/semgrep.exe' --jobs 2 --output "$runRoot/python-official"
```

下一轮优先保留未参与调优的真实漏洞/修复版本和安全项目，补 Python 包装与对象传递、Java 静态资源路径、JS/TS Sequelize 原始查询。先写可复现漏报与安全反例，再决定启用范围；本轮没有把这些尚未实现的能力记成完成。
