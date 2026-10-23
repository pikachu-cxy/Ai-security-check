# 开发脚本

从仓库根目录、在已安装项目依赖的 Python 环境中运行脚本。

| 目录 | 用途 | 示例 |
| --- | --- | --- |
| `build/` | wheel、受管 wheel、独立包构建和内容校验 | `python scripts/build/verify_package.py --wheel dist/example.whl --offline` |
| `release/` | 平台包验证、发行元数据、包管理器清单和发布流程 | `python scripts/release/prepare_release_assets.py --help` |
| `maintenance/` | 同步 Skill、生成第三方声明、校验发布元数据 | `python scripts/maintenance/sync_review_skill.py --check` |
| `benchmarks/` | 架构、上下文、规则和扫描性能测量 | `python scripts/benchmarks/context_cost_benchmark.py --help` |
| 当前根目录 | 验收、规则、诊断和历史重建工具 | 后续按调用关系分批归组 |

目录迁移分批进行，移动脚本时同步修改 CI、文档、动态加载调用和 `MANIFEST.in`。维护脚本的 `--check` 是只读校验；性能脚本可能执行真实扫描或测试，应先查看各脚本的参数与边界。

`python scripts/maintenance/check_repository_layout.py` 只读检查脚本及其嵌入式 Python 的 Runtime 模块引用、CI 文件入口、源码清单和维护导航的本地链接。它不执行脚本、不扫描项目、不安装组件，也不发布资产。构建与发布脚本保持单份实现；不要在旧位置新增转发副本。

归组后的测试见[测试导航](../tests/README.md)，后续工作见[近期计划](../docs/NEXT_DEVELOPMENT_PLAN.zh-CN.md)。发布脚本可能写入远程资产，目录导航不表示授权执行发布。
