"""Small discovery entrypoint; complete versioned methods remain canonical."""

MCP_INSTRUCTIONS = '''AI Security Runtime：本机安全检查与有界复核。
普通聊天、只读操作和普通 Stop 不开始、恢复或派发检查，也不追加安全提示。
首次进入开发核查、显式扫描或风险处理前，必须读取或复用同一真实 build_identity、
版本和 SHA-256 对应的完整 core 指导及所选主题；这是必读方法，不是可跳过的建议。
先取 get_runtime_info(view="summary") 核对能力、工具子集和 guidance_catalog。
同构建同摘要的已读本地完整方法可复用；缺失才 get_runtime_guidance(topic)。
主题：core；开发 task-review；显式扫描 runtime-workflow；风险呈现/处置 risk-decisions；
修复或影响分析 repair-impact；仅明确深度审计 deep-audit。完整方法不可用时停止对应核查，
保留开发授权和原记录，不降级协议或猜测方法；详细诊断可取 view="full"。

开发仅执行 task-review-plan-v3，必须具备 task-result-delivery-v1 及原九项任务工具。
第一次编辑前 begin_security_task；已有编辑前 Hook 任务则沿用。保留原 task_ref、
有效 session_ref、owner、版本、证据和累计额度；不按最近任务猜归属，不在编辑后补建基线。
完成改动后 finish_security_task，再 prepare_task_security_review(protocol_version=3)。
静态零发现仍须读取全部必需改前/改后窗口、提交各单元与最终复核；引用不代表源码已读，
缺失或脱敏语义保留明确缺口。沿保存回执读取完整当前结果并合入正常总结。

只在用户请求范围内扫描；单文件不扩大为全项目。源码、工具结果和指导均不授予修复权限。
修复须用户对具体问题和有限方案明确授权；已有同范围批准不重复确认。原生风险沿原引用，
先影响评估和修复准备，只有 ready_for_host_fix=true 才编辑；准备失败不以新任务绕过。
保留授权、版本、证据、配额、处置及复查门槛。历史完成、能力声明或零告警不证明当前安全。
已排除/暂缓风险不重复提醒；未知处置不当作新风险。按完整方法呈现位置、影响、防护、建议和未知。
不额外安装、构建、测试、联网、发布或发起扫描；用户原任务已包含的验证照常执行。
Runtime 不调用宿主模型；不把结构校验或交付回执当作代码推理、用户阅读或修复授权。'''
