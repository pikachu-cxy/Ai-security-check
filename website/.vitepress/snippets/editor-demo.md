新建空文件夹 `security-runtime-demo`，用刚接入的编辑器打开，在新聊天中发送：

```text
请确认当前目录是独立的 security-runtime-demo 示例目录，在需要时初始化 Git。
新建 labels.py，实现 normalize_label(text)，去除首尾空格并转为小写。
完成后使用 AI Security Runtime 检查本次改动，说明实际检查范围和结果。
无需安装业务依赖；发现风险先解释，不自动修复。
```

检查项目需要 Git。如果提示缺少 Git，先按编辑器的正常指引安装，再重试；安装 Runtime 本身不要求 Git。

**你应看到**文件创建结果，以及针对本次改动的实际检查状态。组件未就绪或检查未完成时应给出原因，文件创建成功不能代替检查成功。

接着完成[已知命令拼接问题 Demo](/guide/demo.md)或[动手测试用例](/guide/playground.md)，验证发现问题、选择修复和沿原问题复查的过程。
