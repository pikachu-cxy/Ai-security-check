# 第一个使用 Demo

用一个小型 Python 例子，体验从发现问题到修复复查的过程。你只需要已完成[安装验证](./verify.md)的编辑器和 Git；**不用启动服务、安装 Python 依赖或执行示例函数**。

<div class="doc-journey" aria-label="Demo 流程">
<span><b>01</b> 准备示例</span><span><b>02</b> 发起检查</span><span><b>03</b> 看懂问题</span><span><b>04</b> 修复并复查</span>
</div>

## 1. 准备一个独立示例项目

新建空文件夹 `security-runtime-demo`，在其中打开终端并执行：

```sh
git init
```

用已接入的编辑器打开这个文件夹，新建 `demo.py`，粘贴以下代码并保存。无需提交 Git。

```python
import os


def export_report(name: str) -> int:
    return os.system("tar -czf " + name + ".tar.gz reports")
```

这是故意保留命令拼接问题的静态检查样例。只把它放在独立示例目录中，不运行它，也不合并到业务项目。

## 2. 在编辑器聊天中发起检查

```text
请使用 AI Security Runtime 检查当前示例项目的 demo.py。
只做静态检查与代码分析，不执行示例函数、不安装项目依赖、不修改代码。
告诉我实际检查范围、发现的问题和触发条件。
```

手动 MCP 接入也使用这条请求。如果只返回普通代码建议，没有实际检查范围与执行状态，继续要求助手说明服务是否调用成功；不要把文字建议当作已执行检查。

## 3. 你会怎样看到问题

下面是**说明形式的示意**，不是预先生成的扫描结果。实际结果以你的规则、组件和检查记录为准。

<div class="doc-example">

**位置：`demo.py` 的 `export_report` 函数**

`name` 被拼接到传给 `os.system` 的命令中。如果调用方允许外部用户控制文件名，Shell 可能把其中的特殊字符解释为额外命令。

建议改用参数列表调用进程，并校验允许的文件名。本例未提供真实调用入口、权限判断或部署环境，因此不能直接认定线上可利用性。

</div>

重点看具体位置、输入如何到达危险操作，以及哪些前提还没确认。若没有发现该问题，先查看 Python 规则是否实际执行、文件是否纳入范围、检查是否完成；不要只对比告警数量。

## 4. 选择修复，再检查原问题

先确认上一步已经给出具体风险，再回复：

```text
请修复刚才 demo.py 中将 name 拼接进 Shell 命令的问题。
保留导出功能，校验文件名并使用参数列表调用进程。
完成后沿原问题复查，说明修复依据；不要执行示例函数。
```

一种可供对照的修改方式：

```python
import subprocess


def export_report(name: str) -> int:
    if not name.isidentifier():
        raise ValueError("Invalid report name")
    return subprocess.run(
        ["tar", "-czf", name + ".tar.gz", "reports"],
        check=False,
    ).returncode
```

现在 `name` 不再通过 Shell 解析，且文件名受校验约束。这只解决本例展示的命令拼接问题；真实项目仍需结合导出目录、权限和调用入口判断。

**Demo 完成标志**：你看到实际检查结果、明确选定了修复的问题，并收到了对应原问题的复查说明。若检查未完成，保留未完成原因；无需为让演示“通过”而排除风险。

[继续做对照测试 →](./playground.md) · [回到日常使用](./workflow.md)
