# 内置规则 1.4.0：多语言基准测试

本次保留仓库默认规则和手动 `--rules` 配置，没有引入在线更新体系。新增 Go 4 条、PHP 6 条、JS/TS 共用 2 条；总计 68 条独立规则，60 条默认启用。

**结论：规则覆盖有所增加，但真实项目测试仍暴露明显误报与漏报，不能用合成用例通过代替检测质量结论。** 本次没有修改基准源码，也没有根据测试结果改写标签。

## 方法与版本

使用 Semgrep **1.178.0**，从产品 `plan_rules` 选取实际默认启用规则，生成本地 YAML 配置。直接运行静态引擎，不安装或启动靶场应用，不把密钥、依赖或 AI 分析算作 SAST 规则命中。本次也不合并原生 dataflow / dynamic-function 检测器结果。

逐文件与固定 Git 提交的原文比对，记录 SHA-256，扫描前后再次确认源码未变。使用 `--time` 和 JSON 中的 `paths.scanned` 核对执行规则、文件和解析错误；这些是规则集合与文件集合证据，不是每条规则在每个文件上的逐项执行证明。

| 项目 | 固定提交 | 本次源码范围 | 文件数 | 执行规则数 | 告警位置数 |
| --- | --- | --- | ---: | ---: | ---: |
| [DVWA](https://github.com/digininja/DVWA/tree/a1978a2fed195acd093010af6395f86a281537ca) / PHP | `a1978a2fed195acd093010af6395f86a281537ca` | vulnerabilities 下 Git 跟踪的 PHP 文件 | 155 | 6 | 35 |
| [GoVWA](https://github.com/0c34/govwa/tree/4058f79f31eeb4a36d8f1e64bba1f0c899646e6f) / Go | `4058f79f31eeb4a36d8f1e64bba1f0c899646e6f` | Git 跟踪的全部 Go 文件 | 20 | 4 | 0 |
| [NodeGoat](https://github.com/OWASP/NodeGoat/tree/c5cb68a7084e4ae7dcc60e6a98768720a81841e8) / JS | `c5cb68a7084e4ae7dcc60e6a98768720a81841e8` | app 下 JS 文件，排除 vendor | 19 | 8 | 1 |
| [OWASP BenchmarkPython](https://github.com/OWASP/BenchmarkPython/tree/f1291485808b66e20ddb6b01b10dc71b3df8c8ba) | `f1291485808b66e20ddb6b01b10dc71b3df8c8ba` | 五类漏洞的有限 testcode 子集 | 92 | 16 | 27 |

四个项目所选文件均实际扫描，返回的解析错误列表均为空。**告警数不等于确认漏洞数，零告警不等于安全。** GoVWA 存在本次四条 Go 规则尚未建模的 SQL、XSS、XXE 等方向。

## 按漏洞类型观察

| 项目 / 类型 | 结果及边界 |
| --- | --- |
| DVWA / 命令注入 | `exec/source/low.php` 两处 shell_exec 被命中；`impossible.php` 的两处调用也被告警。后者先校验并重组四个数值段，当前规则缺乏该防护模型，属于需处理的误报。不能将 `is_numeric` 全局视为命令安全净化函数。 |
| DVWA / SQL 注入 | `sqli/source/low.php:11` 和 `sqli_blind/source/low.php:13` 被命中；对应 impossible 文件未告警。其他 22 处 SQL 告警尚未全部逐条判定，不计为确认真阳性。 |
| DVWA / 反射 XSS | `xss_r/source/low.php` 将输入拼接到 `$html`，输出发生在其他文件，本次规则未命中。当前 echo 模型不能代表跨文件 HTML 拼装覆盖。 |
| DVWA / 文件包含 | `fi/source/low.php` 读取 page，另一个文件执行 include，未命中。需要 include 数据流模型，不能靠任意变量名匹配补齐。 |
| GoVWA / SQL 注入 | 请求参数进入 `Profile.UnsafeQueryGetData`，在另一个文件拼接 SQL 后调用 `DB.Query`。四条 Go 规则没有 SQL 模型，零告警对应未覆盖该漏洞类型。 |
| GoVWA / XSS、XXE | 不在本次新增 Go 规则的建模范围；不能因为 Go 文件已被扫描而宣称这些类型覆盖。 |
| NodeGoat / SSRF | `app/routes/research.js:16` 的 needle.get 命中，来源是请求控制 URL 拼接。 |
| NodeGoat / 动态代码执行 | contributions.js 的三处 eval 未由这八条 YAML 规则命中；原生动态代码检测器属于另一套能力，本表未执行、未计入。 |

## Python 标签子集

使用上游 `expectedresults-0.1.csv`，标签文件也与固定提交核对。按上游文件顺序，每个类别、每种真假标签取前 10 项；不足 10 项时保留实际数量，选择发生在扫描之前。此次没有选到 SSRF 类别。

以下按“同一 testcode 文件 + 对应规则类别”统计；codeinj 对应 code-injection，包括 CWE-95 eval 子类型，不能仅因上游标 CWE-94 就忽略它。**这是文件级子集观察，不是官方完整 Benchmark 得分，也不是生产准确率。** helpers、templates 和其他依赖未纳入本次静态范围，跨文件防护和漏洞链均有局限。

| 类型 | 上游有漏洞文件命中 / 总数 | 上游无漏洞文件告警 / 总数 |
| --- | ---: | ---: |
| 路径遍历 | 1 / 10 | 1 / 10 |
| SQL 注入 | 1 / 5 | 0 / 10 |
| 代码注入 | 5 / 10 | 6 / 10 |
| XSS | 0 / 10 | 0 / 10 |
| 命令注入 | 6 / 10 | 7 / 7 |

例如路径样本包含 request.cookies、URL 解码与 codecs.open 组合；现有模型不能完整追踪。上游无漏洞的代码/命令样本仍大量告警，说明数据流和防护辨识比继续增加相似规则更值得优先投入。所有未命中和误报都保留在结果中，没有从分母删除。

## 验证记录与复现

- 内置全量规则门禁：68 条规则，213 个正例、186 个反例通过，精确核对预期命中行及意外告警。
- 定向回归：109 项测试通过，另有 6 项 subtest 通过；包含 Go/PHP/JS/TS 选择、执行证据、Vue 部分覆盖、本地规则替换和合规元数据。
- wheel 构建及 `scripts/build/check_wheel.py` 核对通过，67 个规则 YAML 文件均包含在包内（文件数与 68 条规则不是同一计数）。没有发布或替换已发布安装包。
- TypeScript 在新增规则的合成用例中验证；本次没有独立 TypeScript 真实项目或 Java 基准运行。
- Vue SFC 仍不声明默认覆盖。

本机完整证据保存在 `.tools/rules-benchmark-20261022/`：`run.py`、每个项目的 `*-inventory.json`（提交、原文 hash、所选规则与文件）、原始引擎 JSON、`*-findings.json`、`summary.json` 和 `python-cases.json`。临时目录不纳入发行包，不复制第三方靶场源码到产品规则目录。

扫描命令的共同参数：

```text
semgrep scan --config <project-rules.yml> --metrics off --disable-version-check
  --json --quiet --time --jobs 2 --no-rewrite-rule-ids --no-git-ignore <selected files>
```

具体参数及批次文件列表保存在 `summary.json`。内置规则回归执行 `python scripts/test_rules.py`。

## 后续优化顺序

1. 将上述上游负例作为防误报验证集，优先修正 Python 命令/eval 及 PHP 命令、SQL 防护辨识；避免用宽泛 sanitizer 掩盖漏洞。
2. 补充 Go database/sql 和常见 Web 框架的输入模型，再验证跨函数参数与 SQL 构造；单文件模式与跨文件能力分别统计。
3. 补充 PHP include/HTML 拼装和 JS 控制器包装的数据流；保持原生检测器与 YAML 规则结果分开归因。
4. 再做 Vue 的 script/setup 解析、模板输入与原始位置映射专项；加入独立 TS、Java 项目及新项目留出集。
5. 每次改规则重跑相同固定提交、相同标签与范围，分别比较误报和漏报；本轮已观察的项目以后作为回归集，不能再当作独立未知测试集宣传。
