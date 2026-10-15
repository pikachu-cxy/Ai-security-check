# 0.3.4 发行 Node 宿主前置探测阻碍

只本地修复候选，尚未推送、重跑 CI 或发布。基于组合候选 1a1d608（远端映射90dc676），不改 Runtime、安全扫描或宿主目标执行预算。

## 直接证据与归因边界

Release run38597591272 的两次 Windows job（115968262472 / 116000892590）均在 tests/test_arithmetic_regression.py::test_real_host_execution_preserves_values_json_and_blocks_fixed_marker 失败。命令为环境PATH中的 C:\Program Files\nodejs\node.EXE --version，subprocess timeout=5；失败发生在固定模板启动前。第二轮记录1 failed、3092 passed、49 skipped、26 xfailed、6 subtests，后续发行门槛未执行。完整失败位置和runner信息节选保存在任务外层 node-failure-attempt-1/2-excerpt.log。

两次runner均为Windows Server2025、image windows-2025-vs2026 20260925.250.1、runner2.337.0。旧tests.yml只设置Python，没有设置Node；测试每个实际宿主用例重复探测环境Node，缺少Node或非24版本时直接skip。现有日志未记录成功返回的Node版本，也没有CPU/IO/杀毒事件，因此不能断言具体系统卡顿原因或该失败Node就是哪个版本。其他同head绿色结果若含更多skip，不是实际宿主通过证明。

可以确定并修复的是前置依赖不确定、无早期诊断、重复且过紧的启动探测，以及不支持环境可通过skip逃离宿主验收。不能将底层偶发stall已被本地彻底排除作为结论；新runner同提交CI仍需验证。

## 最小修复范围

- tests.yml明确使用官方actions/setup-node@v4、精确Node24.16.0、check-latest=false，当前Windows/Mac矩阵和全部测试/规则门槛保留。
- 在依赖安装和长测试前执行独立preflight。只启动node --version，不读执行目标模块；记录实际路径、版本、可执行文件SHA和耗时。首次成功回执上传为本次CI artifact，旧回执拒绝复用，异常非零，没有continue-on-error。
- 该一次启动/readiness探测最多30秒、只有一次，不循环重试。原5秒只包围环境版本进程，并非产品安全预算。30秒是明确独立的前置启动允许值，配合固定版本与早期检查，避免运行一小时才发现依赖未就绪；不是断言runner正常启动需要30秒。
- pytest宿主fixture按session实际探测一次，而不是每个用例重复启动。没有pytest.skip；缺失、不支持/非预期版本、非零或超时均失败。执行前重新核对Node二进制内容SHA，不能由同路径或mtime复用被替换的exe。仅清理该子进程的NODE_OPTIONS/NODE_PATH，与既有worker环境处理一致，不改用户环境。
- 五个真实宿主执行用例保留；成功的32项算术比较/JSON语义/标记拒绝报告与Node身份另存CI artifact。缺少报告按error处理，不仅凭版本探测成功判宿主通过。

src/security_runtime及固定模板字节均未改：宿主执行仍为计划内30秒，worker10秒，权限模型禁止子进程和文件写入；网络能力仍UNKNOWN，不把Node权限模型宣称完整沙箱。未删除发布门槛、扩展生产预算或安装/更改用户系统依赖。

## 来源与本地实测

公司电脑已有Node v24.16.0；未下载新本地依赖。五次版本启动观察约27.7–51.3ms（node-local-probes.json），不是runner稳定分位数。独立preflight含exe完整SHA读取为146.317ms。

版本及二进制来源核实：[Node官方24.16.0 LTS发行说明](https://nodejs.org/en/blog/release/v24.16.0)、[官方SHASUMS256](https://nodejs.org/download/release/v24.16.0/SHASUMS256.txt)。本地win-x64/node.exe SHA256 b3094d0b49f9ad602262a9921551737bb97637c05dd357a06ae98188d7290aa3，精确匹配官方清单。[官方setup-node说明](https://github.com/actions/setup-node)支持固定node-version并建议不依赖系统PATH版本。CI将通过现有官方action取得精确版本；没有新增凭据/私有镜像/付费服务。

最终定向70 passed、0 failed、0 skipped，22.46秒（node-fix-final-tests.log / .xml / node-fix-final-execution.json）。包括12项算术测试（五项真实Node宿主执行）、12项前置探测/CI配置回归、原46项组合与新鲜度/报告/版本检查。超时、缺失、非24、预发布/畸形版本、exact版本不符、非零探测、旧回执均不能通过；超时只调用一次，原预算回归明确保持30/10秒。

实际宿主证据 node-fix-host-evidence/arithmetic-host-positive.json：ACTUAL_HOST_FIXTURE_PASSED，Node24.16.0，进程exit0，ARITHMETIC_REGRESSION_PASSED，32项比较，修复前受控标记1/后0；没有HTTP server执行。测试只运行仓库内已审阅的固定自有TS夹具，未执行公司/用户业务应用或其他不可信项目。

这是本地候选证据，不是远端Windows/macOS、新原生包或最终发行通过。交独立复核后，仍需同新提交完整CI及适用发行门槛；0.3.3公开版本不改，也没有继续重跑旧失败流水线。

## workflow上下文位置修正

远端候选8a0df5a4d4b1b5931269399df6afacd56b302d2c的Runtime run38620035606在runner开始前立即失败，jobs API返回0个job；其他Compliance及Package integrity通过不能替代Runtime门槛。发现本候选错误地把runner.temp放在job级env，此前YAML解析回归没有验证上下文可用位置。[GitHub官方上下文表](https://docs.github.com/en/actions/reference/workflows-and-actions/contexts#context-availability)明确job env不允许runner，step env允许。此次只将SECURITY_RUNTIME_HOST_REPORT_DIR移入Run Runtime tests步骤的env，补充位置断言；Node版本、预检、实际宿主执行、artifact、生产预算和发行门槛均保留。未读取到远端validation annotation原文，根因依据失败阶段与已确认的非法上下文位置；最终仍需修正提交的远端runner通过。
