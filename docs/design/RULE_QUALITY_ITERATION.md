# 本地规则评估与迭代

更新日期：2026-10-16。本批为源码规则包 1.3.1 候选，不代表已发布或替换本机安装。

后续 Java/Python 跨函数、跨文件数据流改进及同源前后对比见
[第 2 轮数据流优化](BOUNDED_DATAFLOW_ITERATION_20261016.md)。下文保留第一轮原始结果。
进一步的构造器、服务字段、Python 参数绑定、路径子集及性能对比见
[第 3 轮数据流优化](DATAFLOW_ROUND3_20261016.md)。
循环退出、Python 流 API 子集及官方默认规则的同源对照见
[第 4 轮优化与 Semgrep 对照](DATAFLOW_ROUND4_SEMGREP_20261016.md)。

后续规则与官方对照见[第 6 轮报告](DATAFLOW_ROUND6_20261016.md)，当前增量缓存候选见[第 7 轮报告](DATAFLOW_ROUND7_INCREMENTAL_20261016.md)。下文保留本文件原始轮次的范围与结果，不作为当前规则数量。

## 本轮采用的改进

- Python SQL 注入：增加 Flask Cookie、Header 的显式输入建模；绑定参数值仍与 SQL 模板分开。
- JS/TS SSRF：增加成员箭头函数请求处理器的局部输入建模，以及有模块导入依据的 `needle.get` 地址参数。
- 仅修改上述两个规则身份；55 条内置规则、47 条默认启用及 8 条 Java 默认关闭规则均不变。
- Java 规则没有借本批提升成熟度；没有下载或移植外部规则。新增正反例为本项目独立编写。

完整本地回执位于忽略目录 `artifacts/rule-quality-20261016/`，原始失败、拒绝候选与最终回执分别保留。

## 语料与观察单位

| 语料 | 本批实际范围 | 标签依据 |
| --- | --- | --- |
| 本地 OWASP BenchmarkJava | 原有 180 例复测；另测全部 SQL 类的 416 个开发样本 | 上游 CSV 与本地 Git 对象逐文件核对 |
| 本地 Jeepay | 512 Java + 36 XML；原有 SQL、命令、SSRF、文件相关范围 | 无完整漏洞真值，不能计算召回率 |
| OWASP BenchmarkPython | SQL 16 例、路径 168 例；140 开发 / 44 保留 | 上游 CSV，版本 0.1，提交 `f1291485808b66e20ddb6b01b10dc71b3df8c8ba` |
| OWASP NodeGoat | 42 个应用源码文件；静态规则与独立动态代码词法检查 | 上游教学项目 + 有限代码复核，无完整计分标签 |
| 本地 DeepAudit backend | 167 个源码文件 | 无完整漏洞真值，零发现不证明安全 |

官方来源：[BenchmarkPython](https://github.com/OWASP-Benchmark/BenchmarkPython)、[NodeGoat](https://github.com/OWASP/NodeGoat)。
外部源码只读，不导入、不构建、不安装依赖、不启动服务。外部许可证源码留在忽略的语料目录，不进入产品规则或分发包。

计分单位是“上游文件及漏洞类别”，不是发现条数，也不是逐 sink 或生产准确率。
扫描失败、文件缺失、适用规则未执行均为无法判断，不计作 FN/TN。
划分在扫描前由 case ID 的固定哈希确定。生成式基准的相似模板可能跨两组出现，不能声称模板独立或生产分布代表性。
保留组一旦用于验收，就不能再称下一轮的未见数据；下一轮必须另留未参与调优的语料或模板组。

## 实际采用与拒绝

| 候选 | 开发样本变化 | 验收决定 |
| --- | --- | --- |
| Java JDBC API 宽泛补全 | SQL TP 15→24，FP 8→15；416 例 | 拒绝；没有进入产品规则 |
| Python 路径候选 1 | TP 1→4，FP 5→7；129 个路径开发例 | 拒绝 |
| Python 路径候选 2 | 开发 TP 1→3，FP 仍为 5；保留 TP 1→2、FP 1→2 | 拒绝；没有按保留样本继续调参 |
| Python SQL 输入补全 | 开发 TP 0→1，FP 仍为 0；保留 TP/FP 均未变 | 采用；全部 16 例最终为 TP 1、FP 0、FN 4、TN 11 |
| JS/TS SSRF 输入与客户端补全 | NodeGoat 原来遗漏的 research 控制器位置被检出 | 结合源码与安全对照例采用；不据此计算准确率 |

NodeGoat 的路由在 `app/routes/index.js` 绑定 `researchHandler.displayResearch`；
`app/routes/research.js` 将请求 URL 和 symbol 组合后交给 `needle.get`，没有在该路径观察到地址允许列表。
扫描器只证明局部匹配；路由关系来自宿主代码复核，不是全程序跨文件分析引擎的证明。
原有三处 eval 候选保持检出。DeepAudit 前后均零发现，不能当作已确认安全负例。

Python 路径规则最终保持原样：全部 168 例仍有 TP 2、FP 6、FN 63、TN 97。
Java 的跨函数、跨文件、集合、常量分支等既有边界仍保留，不能通过宽泛追加输入/API 掩盖。

## 复现方式

项目 Python 3.12 环境及固定版本扫描引擎须已准备。命令在仓库根目录运行：

```powershell
$env:PYTHONPATH = (Join-Path (Get-Location).Path 'src')
$env:PYTHONUTF8 = '1'
$env:SECURITY_RUNTIME_OFFLINE = '1'

# 每次选择全新的输出目录，旧证据不能被覆盖。
.\.venv\Scripts\python.exe scripts/rule_quality_evaluation.py `
  --root '<本地 BenchmarkPython 路径>' --kind python --split train `
  --output artifacts/rule-quality-next/python-train

# 冻结规则后才验收 holdout；查看结果后不再将该组称作未见数据。
.\.venv\Scripts\python.exe scripts/rule_quality_evaluation.py `
  --root '<本地 BenchmarkPython 路径>' --kind python --split holdout `
  --output artifacts/rule-quality-next/python-holdout

.\.venv\Scripts\python.exe scripts/rule_quality_evaluation.py `
  --root '<只读真实项目路径>' --kind unlabelled `
  --output artifacts/rule-quality-next/real-project
```

`--groups` 可显式选择类别；默认只测 SQL 和路径，不能当作全类别扫描。
`--reference` 可用本地 Git 对象校验解压版源码；参考对象不可读或内容不同就停止。
`--pack` 可比较保留的本项目第一方规则快照，仍验证规则来源、身份和版本。
每次评估使用输出目录内的独立 Semgrep 设置和日志，不修复或覆盖用户级设置。

## 持续迭代门槛

1. 先冻结标签、语料版本、划分和原始规则，再测基线。
2. 从开发样本定位具体 API/控制流缺口，写安全与危险对照例，不使用基准文件名作为检测条件。
3. 候选先在隔离快照验证；新增误报需解释并阻止直接进入默认规则。
4. 候选冻结后验收保留组，保留所有失败记录；不要修改真值、抹掉已知失败或关闭检查换取通过。
5. 跑全规则正反例与关联回归，再对至少一个真实项目观察变化。无真值不算准确率。
6. 分别记录源码回归、开发任务安全核查、原生包和宿主验收；它们互不替代。

下一轮优先处理 Java 及 Python 的常量分支、容器与函数返回传播边界，再补其他框架的独立语料。
8 条默认关闭 Java 规则仍需逐条质量依据和启用条件，不能批量开启。
