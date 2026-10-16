# Java / Python 数据流优化：第 2 轮

日期：2026-10-16。状态：源码候选，尚未打包或替换本机安装版本。

本轮补充有界 AST 分析，默认用于功能级和项目级扫描的 SQL 注入检测。
它解析本地函数、模块导入、部分对象字段、参数和返回值，并保留输入、调用位置、危险参数及相关源文件哈希。
目标项目始终只读：不导入、不构建、不安装依赖、不启动服务。

## 同源、同标签对比

计分单位是“文件 + 漏洞类别”，不是告警条数、逐危险操作覆盖率或生产准确率。
比较器验证案例集合、标签、划分和源码哈希相同；未完成评估不能通过比较门槛。

| 范围 | 案例 / 阳性 | TP 前→后 | FP 前→后 | FN 前→后 | 召回率前→后 |
| --- | --- | --- | --- | --- | --- |
| Java SQL 全部 | 504 / 272 | 19→113 | 10→10 | 253→159 | 7.0%→41.5% |
| Java SQL 开发组 | 416 / 226 | 15→92 | 8→8 | 211→134 | 6.6%→40.7% |
| Java SQL 保留组 | 88 / 46 | 4→21 | 2→2 | 42→25 | 8.7%→45.7% |
| Python SQL 全部 | 16 / 5 | 1→5 | 0→0 | 4→0 | 20.0%→100.0% |
| Python SQL 开发组 | 11 / 3 | 1→3 | 0→0 | 2→0 | 33.3%→100.0% |
| Python SQL 保留组 | 5 / 2 | 0→2 | 0→0 | 2→0 | 0.0%→100.0% |
| Python 路径全部 | 168 / 65 | 2→2 | 6→6 | 63→63 | 3.1%→3.1% |

Java SQL 精确率由 65.5% 提升到 91.9%；已有误报仍然保留，没有删除或重标标签。
Python SQL 只有 5 个阳性，100% 不能推广成该语言的总体检出率。
Java 仍漏报 159 个 SQL 阳性，Python 路径仍漏报 63 个阳性。

上游版本沿用上一轮固定提交：BenchmarkJava `b06d6efaebd577a327514364951916e7df3290b4`，
BenchmarkPython `f1291485808b66e20ddb6b01b10dc71b3df8c8ba`。
划分以固定 case ID 哈希产生，可能共享生成模板；保留组经本轮验收后不再是未见数据。
上一轮已观察过 Python 保留组，因此本轮该组属于回归验收。

## 每次候选的取舍

| 候选 | 观察 | 处理 |
| --- | --- | --- |
| 初始 Java SQL 数据流 | 开发组 TP 15→90，FP 保持 8 | 保留；继续补参数 Map、字符串构造及已绑定 Spring 入口 |
| 初始 Python SQL 数据流 | 开发组 TP 1→3，FP 保持 0 | 保留 |
| Python 路径数据流实验 | 开发组 TP 1→7，但 FP 5→8 | 不进入默认检测；不把 `../` 检查泛化成安全路径证明 |
| 最终默认 SQL 数据流 | Java 开发组 TP 92、FP 8；Python 开发组 TP 3、FP 0 | 结合保留组与真实项目观察，作为有明确边界的源码候选 |
| 真实 Python 项目兼容性 | 歧义对象导致的文件级分析异常从 5 个降至 0 个 | 不猜测动态类型；标记未知并继续其他代码 |

现有核心静态规则仍为 55 条，其中 47 条默认启用、8 条 Java 实验规则关闭。
新增数据流提供方独立统计：6 个实验规则身份，Java/Python 各 3 个；默认只选两种语言各 1 个 SQL 规则。
路径与命令规则仅能通过评估接口显式启用实验模式，不能算作新增默认覆盖。

## 跨文件证据与误报约束

公开基准的新增提供方结果中，Java 有 12 条、Python 有 2 条跨文件证据链。
例如 Java `SeparateClassRequest.java:31` 的请求输入，经 `BenchmarkTest00043.java:46` 调用，
到达该文件第 54 行的 SQL 操作；Python `helpers/separate_request.py:10` 经
`BenchmarkTest00283.py:34` 到达第 49 行 SQL 操作。
相关哈希和调用位置保存在各批次回执中。独立编写的跨文件正反例另覆盖参数、返回值、对象字段和下游危险调用。

常量返回、参数化 SQL、同名本地类型、同参数数量的歧义重载、未知函数返回、非路由注解和数值路由参数有反例约束。
未知调用不会无条件继承所有参数的污染；反射工厂也没有针对基准硬编码其返回实现。
与旧检测结果同位置合并时，保存补充证据，不替换原规则身份。

## 真实项目与耗时

| 项目 | 实际范围 | 观察 |
| --- | --- | --- |
| Jeepay | 558 文件：512 Java、36 XML、10 JS | 前后均保留 1 个原有 TLS 候选；数据流未新增候选 |
| DeepAudit backend | 167 Python 文件 | 前后均零候选；最终无文件级异常，仍有未建模语义 |
| SpringVulnBoot-backend（教学） | 119 文件 | 原静态结果之外补充 8 个 SQL 数据流候选；待人工逐项复核，无完整真值 |

这三个项目没有完整独立标签，不能计算精确率或召回率。没有新增候选不代表没有漏报。
DeepAudit 对比复用了上一轮相同源码、相同核心规则哈希的观察；Jeepay 重新执行了前后两次同范围扫描。
Spring JDBC 参数化查询的安全对照未新增告警；自定义过滤器的有效性仍未知。

新增 AST 分析的单次基准批次合计耗时约 Java 14 秒 / 504 文件、Python 0.5 秒 / 184 文件，
Jeepay 约 20 秒 / 512 Java 文件、DeepAudit 约 1.3 秒 / 167 文件。
这些是本机观察，包含缓存和负载影响，不能当作性能承诺。
没有把新提供方加入文件编辑 Hook 或 quick 模式，因此本轮新增分析不会在每次编辑时执行。

产品单次大范围调用自动按 80 个目标拆分，批内最多 256 个上下文文件、8 MB、100 万抽象步骤、调用深度 6。
30 秒后停止发起新批次，未分析目标明确记为未完成。取消请求在目标和批次之间检查。
另以一次真实调用校验完整 Java、Python、Jeepay 语料，与外部逐批评估的发现和证据链完全一致。

## 能力边界与后续顺序

Java 解析器当前支持 Java 8；无法解析的新语法会给出部分覆盖，旧静态检测仍独立保留。
反射、运行时导入、歧义重载、复杂继承、未知集合、未建模循环、框架注入和 SQLAlchemy/MyBatis 等仍有缺口。
这是有界分析子集，不是完整调用图或全程序可达性证明，零结果不能证明修复成功。
该提供方明确不具备“未检出即修复通过”的资格，现有修复复查门禁保持保守。

下一轮优先：为 MyBatis/XML、Spring 服务层和 FastAPI/SQLAlchemy 建立可独立复核的正反例真值；
随后处理 Java 反射/动态分派和 Python 路径防护语义。不得把当前已见的保留组再次当作独立盲测。

## 复现与证据

所有命令从本仓库根目录运行；每次指定新的输出目录，现有证据不能覆盖。
现有 `.venv` 已包含固定的 `javalang==0.13.0`、`six==1.17.0`；后续环境通过项目依赖准备。
原始 MIT 许可证保留在包内，发行规格已包含实现文件及依赖元数据；本轮尚未构建新安装包。

```powershell
.\.venv\Scripts\python.exe scripts/rule_quality_evaluation.py `
  --kind java --groups sqli --split all --dataflow `
  --root 'C:/Users/24170/Downloads/BenchmarkJava-master (1)/BenchmarkJava-master' `
  --reference 'C:/Users/24170/Desktop/BenchmarkJava' `
  --output artifacts/rule-dataflow-next/java

.\.venv\Scripts\python.exe scripts/rule_quality_evaluation.py `
  --kind python --groups sqli pathtraver --split all --dataflow `
  --root .tools/rule-quality-20261016/corpora/BenchmarkPython `
  --output artifacts/rule-dataflow-next/python

.\.venv\Scripts\python.exe scripts/compare_rule_quality.py `
  --before artifacts/rule-quality-20261016/python-final-all `
  --after artifacts/rule-dataflow-next/python `
  --output artifacts/rule-dataflow-next/python-comparison.json
```

`--dataflow-experimental --dataflow` 仅用于评估尚未提升的路径/命令规则。
评估保存原始结果、标签划分、源码哈希、引擎回执和数据流实现快照；Git 对象批量读取仍逐文件比较原始内容。
中断、脚本错误、部分分析和被拒绝的候选均保留，不混入最终成绩。

本轮原始目录：`artifacts/rule-dataflow-20261016-r2/`。
最终计分输入是 `java-final-all/` 与 `python-final-all/`；产品一次调用验收为 `runtime-integration.json`。
其余带版本后缀的目录是过程证据；缺少成功汇总的目录不能当作完成结果。
产品回归、基准结果、开发任务安全核查、安装包及宿主验收各自独立，不能互相替代。

相关产品回归最终为 211 项通过、6 项子测试通过，记录在 `pytest-final.xml`。
开发任务自动安全核查的初始准备未完成；上述测试和基准不能证明本轮改动安全。
