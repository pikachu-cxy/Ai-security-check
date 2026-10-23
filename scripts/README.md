# 开发脚本

从仓库根目录、在已安装项目依赖的 Python 环境中运行脚本。

| 目录 | 用途 | 示例 |
| --- | --- | --- |
| `maintenance/` | 同步 Skill、生成第三方声明、校验发布元数据 | `python scripts/maintenance/sync_review_skill.py --check` |
| `benchmarks/` | 架构、上下文、规则和扫描性能测量 | `python scripts/benchmarks/context_cost_benchmark.py --help` |
| 当前根目录 | 尚未迁移的构建、发布、验收和规则工具 | 发布任务继续使用现有入口 |

目录迁移分批进行，移动脚本时同步修改 CI、文档、动态加载调用和 `MANIFEST.in`。维护脚本的 `--check` 是只读校验；性能脚本可能执行真实扫描或测试，应先查看各脚本的参数与边界。
