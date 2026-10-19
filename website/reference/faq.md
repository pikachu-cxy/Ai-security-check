# 常见问题

## 安装为什么这么慢？

完整程序接入与扫描能力准备是两个阶段。首次可能下载引擎、独立运行环境和漏洞数据库；先查看 `preparation status`，用 `preparation watch` 观察进度。不要反复清空缓存后重装。

## 能不下载漏洞库吗？

当前版本不能把“无需本地漏洞库”作为已交付特性。在线与本地双模式已确定为后续优化方向，届时由用户选择。安装方式与未来能力见[安装说明](../guide/installation.md)。

## 每台电脑都能使用 npx 吗？

不能。`npx` 属于 Node.js/npm 工具链，并不是 Windows 或 macOS 自带命令。本项目当前没有正式交付 `npx` 安装入口；完整包也不要求 Node.js。

## 源码已更新，为什么连接的还是旧版？

已安装的完整包不会随 Git 工作区自动更新。重启宿主后读取实际 `get_runtime_info`，核对版本、`build_id` 与配套 Skill，不能只看 README 或版本字符串。

## 只要 MCP，不想安装 Hook 和 Skill？

不要执行默认完整接入命令。按[仅 MCP 指南](../guide/mcp.md)准备组件并生成宿主配置，手动合并；此时不承诺完整任务自动化。

## Cursor 或 macOS 已完全兼容了吗？

不能这样概括。连接器、原生 CI、完整任务和桌面手工验收是不同层次。当前边界见[支持状态](./support.md)，本次 macOS 与 Cursor 的手工验收仍待完成。

## Windows TEMP 路径太长怎么办？

当前源码为 Semgrep 使用短私有临时目录，无需全局修改系统 TEMP/TMP。特殊账户可按诊断配置项目外已有的短本地 `SECURITY_RUNTIME_ENGINE_TEMP_ROOT`。权限或本地通信被沙箱拒绝时，应在获准支持该能力的环境执行，不要关闭系统安全控制。

## “准备成功”代表项目通过检查吗？

不是。安装、组件准备、MCP 连接、项目检查与原风险复查分别记录。普通测试成功也不等于漏洞已修复。

## 如何报告问题？

到 [GitHub Issues](https://github.com/pikachu-cxy/Ai-security-check/issues) 提供脱敏后的系统架构、宿主版本、实际构建身份、失败步骤与具体诊断。不要公开真实凭据、原始聊天或私有源码。
