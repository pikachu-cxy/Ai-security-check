这是 AI Security Runtime 0.3.9 的独立 Mac 安装方式试用，使用专属 Python 环境和标准 Python 包。不会替换历史完整安装包。

从[文档站 Mac 试用页](https://pikachu-cxy.github.io/Ai-security-check/downloads.html)选择 Cursor 或 Codex 的一条安装命令。无需预装 Python、Git 或 Homebrew。首次安装需要联网，检查组件在后台准备。

本发布要求 Apple Silicon 和 Intel 的 GitHub macOS runner 通过离线产品安装、版本身份、编辑器配置及重复安装验收。真实用户 Mac 的系统策略、浏览器首次下载、Cursor/Codex 桌面连接，以及全部检查组件仍需试用验证。该发布不表示具备 Apple Developer ID 签名或公证。

试用会把所选编辑器的 AI Security Runtime 接入切换到试用版本。恢复时，使用原正式完整包重新执行对应编辑器的安装命令，并重启编辑器。扫描、风险关闭和修复授权规则沿用当前产品。

反馈时请提供 macOS 版本、芯片、编辑器版本、Runtime 构建编号、失败阶段及脱敏报错。不要附带业务源码、令牌或密钥。

本次发行同步一键聊天消耗监控和 token / 耗时报告导出、完整脱敏长行证据交付。监控可选且不阻断核心功能，不能可靠拆分的活动 token 仍保持未知。

本次自动安装交付为 macos-trial-v0.3.9.3，包含 0.3.9 正式版的系统 Semgrep 兼容修正：在线准备时，无法核验的自动发现组件不再阻止创建独立受管环境；不改动系统已有安装，不绕过执行身份、离线或显式路径约束。
