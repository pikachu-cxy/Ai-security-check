---
name: ai-security-review
description: Use for explicit security audits, selected risk decisions or authorized repairs with AI Security Runtime.
---

普通 Codex 开发由 Hook 自动记录和收尾，无待办直接完成开发任务。
收到“正在整理安全检查结果”时，读取 view="closeout"，依照 closeout_mode 处理本批结果。REVIEW 才补读证据、沿原检查合并提交；REPORT/INCOMPLETE 只交付完整报告、缺口和会话链接。
用户明确请求扫描、风险处置或修复时，先读 CORE.md，再按请求选读对应方法。
