# 当前架构

<a id="windows-native-engine-execution"></a>

架构的统一维护入口为 [项目字典中的架构](knowledge/ARCHITECTURE.md)。既有 Windows 引擎链接保留此入口；引擎适配及进程执行定位见 [修改导航](knowledge/CHANGE_MAP.md)。

当前产品通过 CLI、MCP 和宿主 Hook 接收请求，工作区应用层验证路由与归属，领域服务负责开发检查、严格复核、显式扫描及风险处理。扫描输入和执行租约约束结果发布，私有存储保存证据与处置。默认开发只观测编辑路径并在收尾合并检查。

- [架构分层与流程](knowledge/ARCHITECTURE.md)
- [功能到代码及测试的导航](knowledge/CHANGE_MAP.md)
- [接口设计与契约](knowledge/INTERFACES.md)
- [当前设计约束](knowledge/DESIGN_RULES.md)

本页仅作为兼容既有链接的入口，架构细节只在知识库维护。
