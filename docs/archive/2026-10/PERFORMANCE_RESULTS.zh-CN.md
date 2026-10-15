# 严格顺序对照测量

本地分页处理优化通过有限范围验收：component 分页中位耗时变化 +28.0%（下降为正），范围不重叠；full 分页中位耗时变化 +29.9%（下降为正），范围不重叠。其他阶段不作为本地分页提速结论的替代，完整产品/桌面/模型语义与发布验收仍未完成。

判定要求：每个规模至少三次不同任务重复、每次三页、执行成功、签名快照与范围一致；两规模分页中位耗时均下降且前后范围不重叠才通过。页读是任务内相关观测，不是独立项目实验。系统文件缓存未清空。

前后签名任务 begin/end 完整哈希集合、项目清单、限制、发现集合、provider 版本/状态/覆盖、扫描范围、能力状态及证据页身份全部一致。脚本提交 PARTIAL，明确未调用模型做语义复核。

component：3 次任务重复；实际签名快照 191 文件/1974197 字节。额外规模探针哈希数前/后 191/191，探针限制 []/[]，不参与任务证明。实际任务限制 [{'path': 'src/security_runtime/task_security.py', 'reason': 'PREIMAGE_OR_TEXT_BUDGET_UNAVAILABLE'}]。

full：3 次任务重复；实际签名快照 660 文件/4345472 字节。额外规模探针哈希数前/后 554/611，探针限制 [{'reason': 'INVENTORY_READ_BUDGET'}]/[{'reason': 'INVENTORY_READ_BUDGET'}]，不参与任务证明。实际任务限制 [{'path': 'src/security_runtime/assets/arithmetic_regression.mjs', 'reason': 'PREIMAGE_OR_TEXT_BUDGET_UNAVAILABLE'}, {'path': 'src/security_runtime/task_security.py', 'reason': 'PREIMAGE_OR_TEXT_BUDGET_UNAVAILABLE'}]。

| 样本/阶段 | 前中位数 ms（范围） | 后中位数 ms（范围） | 中位变化 |
|---|---:|---:|---:|
| component/begin_inventory_hash | 984.0 (972.4–1112.5; 调用数 3) | 994.0 (991.9–1181.8; 调用数 3) | +1.0% |
| component/hook_static | 5951.6 (5455.9–9907.2; 调用数 3) | 5544.7 (5524.2–9806.2; 调用数 3) | -6.8% |
| component/finish_rescan | 6873.2 (6625.3–6947.1; 调用数 3) | 6405.9 (6395.6–6518.3; 调用数 3) | -6.8% |
| component/finish_idempotent | 928.8 (917.8–1145.6; 调用数 3) | 997.5 (991.1–1060.6; 调用数 3) | +7.4% |
| component/prepare | 978.6 (969.2–995.7; 调用数 3) | 708.2 (694.2–717.1; 调用数 3) | -27.6% |
| component/context_page | 1003.6 (959.5–1094.0; 调用数 9) | 723.0 (697.8–735.8; 调用数 9) | -28.0% |
| component/context_repeat_page | 1010.2 (1006.1–1032.3; 调用数 3) | 708.4 (700.3–725.1; 调用数 3) | -29.9% |
| component/host_partial_submission | 1127.1 (1107.5–1135.5; 调用数 3) | 743.2 (742.9–761.3; 调用数 3) | -34.1% |
| component/result_output | 1006.8 (989.2–1008.7; 调用数 3) | 861.1 (795.3–910.3; 调用数 3) | -14.5% |
| full/begin_inventory_hash | 2252.6 (2127.2–3251.8; 调用数 3) | 2136.3 (2093.6–2559.0; 调用数 3) | -5.2% |
| full/hook_static | 6276.8 (6221.0–10951.7; 调用数 3) | 6174.7 (6168.7–10530.8; 调用数 3) | -1.6% |
| full/finish_rescan | 8818.2 (8775.5–9049.3; 调用数 3) | 8310.3 (8237.2–8649.8; 调用数 3) | -5.8% |
| full/finish_idempotent | 2047.2 (2023.1–2146.6; 调用数 3) | 2035.0 (2020.9–2044.9; 调用数 3) | -0.6% |
| full/prepare | 2250.1 (2169.6–2302.4; 调用数 3) | 1442.7 (1424.9–1474.7; 调用数 3) | -35.9% |
| full/context_page | 2105.1 (2069.4–2173.1; 调用数 9) | 1476.6 (1420.4–1507.6; 调用数 9) | -29.9% |
| full/context_repeat_page | 2104.9 (2099.0–2145.7; 调用数 3) | 1526.6 (1514.7–1531.8; 调用数 3) | -27.5% |
| full/host_partial_submission | 2138.4 (2127.0–2146.3; 调用数 3) | 1588.1 (1584.5–1621.9; 调用数 3) | -25.7% |
| full/result_output | 2146.2 (2107.6–2166.8; 调用数 3) | 1461.8 (1460.3–1523.5; 调用数 3) | -31.9% |

## 冷暖缓存单列

缓存标签是任务的启动状态，不代表该任务每页调用时引擎仍处于冷启动。下表实际列出各状态样本数，不推算稳定冷启动中位数或 P95。实际 provider HIT/MISS 留在原始 scanner_diagnostics；它们是准备信息缓存，不是扫描结果复用。

| 样本/阶段/缓存 | 前 ms（中位；范围；n） | 后 ms（中位；范围；n） |
|---|---:|---:|
| component/hook_static/process_first_os_cache_uncontrolled | 9907.2; 9907.2–9907.2; 1 | 9806.2; 9806.2–9806.2; 1 |
| component/hook_static/process_warm_new_task_state | 5703.8; 5455.9–5951.6; 2 | 5534.5; 5524.2–5544.7; 2 |
| component/finish_rescan/process_first_os_cache_uncontrolled | 6947.1; 6947.1–6947.1; 1 | 6518.3; 6518.3–6518.3; 1 |
| component/finish_rescan/process_warm_new_task_state | 6749.2; 6625.3–6873.2; 2 | 6400.7; 6395.6–6405.9; 2 |
| component/context_page/process_first_os_cache_uncontrolled | 1007.1; 959.5–1016.0; 3 | 735.2; 734.4–735.8; 3 |
| component/context_page/process_warm_new_task_state | 997.6; 977.1–1094.0; 6 | 703.8; 697.8–735.1; 6 |
| component/result_output/process_first_os_cache_uncontrolled | 1008.7; 1008.7–1008.7; 1 | 861.1; 861.1–861.1; 1 |
| component/result_output/process_warm_new_task_state | 998.0; 989.2–1006.8; 2 | 852.8; 795.3–910.3; 2 |
| full/hook_static/process_warm_new_task_state | 6276.8; 6221.0–10951.7; 3 | 6174.7; 6168.7–10530.8; 3 |
| full/finish_rescan/process_warm_new_task_state | 8818.2; 8775.5–9049.3; 3 | 8310.3; 8237.2–8649.8; 3 |
| full/context_page/process_warm_new_task_state | 2105.1; 2069.4–2173.1; 9 | 1476.6; 1420.4–1507.6; 9 |
| full/result_output/process_warm_new_task_state | 2146.2; 2107.6–2166.8; 3 | 1461.8; 1460.3–1523.5; 3 |

## 实际读取与重复计算

| 样本/单页 | 前读取次数/字节/脱敏次数/哈希次数 | 后读取次数/字节/脱敏次数/哈希次数 |
|---|---:|---:|
| component | 192 / 2038739 / 192 / 196 | 192 / 2038739 / 1 / 195 |
| full | 661 / 4410014 / 661 / 665 | 661 / 4410014 / 1 / 664 |
前 provider 准备信息缓存观察：{'semgrep/selected_config/HIT': 6, 'semgrep/version_probe/HIT': 6, 'gitleaks/version_probe/HIT': 6}。
后 provider 准备信息缓存观察：{'semgrep/selected_config/HIT': 6, 'semgrep/version_probe/HIT': 6, 'gitleaks/version_probe/HIT': 6}。

这里的哈希次数也包含 Hook revision 与证据身份元数据摘要。分页每次重读项目仍是剩余成本。总重复读取字节、嵌套函数计时、调用数和实际 provider 缓存观察留在原始 JSON；没有静态字符数冒充真实模型 token，没有估算 P95。

早期 Python 单文件阶段的数据与受短暂并发影响的初步 full 观测不用于上述验收。低风险改动确实消除每页一次 raw 哈希，但不能把后续整体阶段变化全部归因于这一微小计算。

真实样本只有一个用户自身项目及其组件投影。未覆盖 Java、Go、TypeScript 或超过 1000 支持文件的大项目；.mjs 仅原有 Function/eval 词法 provider，不证明所有 JavaScript 漏洞能力。依赖扫描在此代码范围不适用，未测依赖数据库；OSV 现有版本不符。Agent token、模型推理耗时和桌面端真实 Demo 未测。详见 PERFORMANCE_REVIEW.zh-CN.md。
