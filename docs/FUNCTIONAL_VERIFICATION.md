# Functional Verification v0.1

本能力独立于安全复核。`SCANNER_VERIFIED_RESOLVED` 的原契约不变；本地命令通过只能证明列出的验证步骤，不能证明生产正确、业务完整或 SAFE_TO_SHIP。

## Runtime 与宿主

`FunctionalVerifierRegistry` → deterministic plan → `FunctionalVerificationService` → `LocalSandbox` → 独立结果。Registry 包含 Maven / Gradle / Node / Python 四个 verifier。现有 HookCoordinator 不运行 build/test；普通 edit 不触发功能验证。

AUTO_FIX 与明确批准后的 USER_CONFIRMED 共用流程：prepare_task_fix → 宿主受限编辑 → 自动 Hook/verify_task_fix → SCANNER_VERIFIED_RESOLVED → prepare_functional_verification → run_functional_verification。Runtime 从原 HMAC remediation record 验证 CLOSED、原 rule/task/member、grant、policy/TTL、source/preservation guard 和当前 security snapshot；不接受宿主声称“已修好”。DECLINED、未授权、仍存在、过期、成员/源码变化都不启动 verifier。批准 grant 仍限原连接。

MCP 新增两个可选工具，Runtime 0.3.1 / developer-guidance-v0.3 保持：

```text
prepare_functional_verification(
  remediation_ref: string,
  task_ref: string,
  workspace_path?: string
)
run_functional_verification(functional_ref: string)
```

两者输入闭合、strict，不回显非法值。没有 argv、command、source、prompt、transcript、Secret、host status 或 network override 字段。prepare 只读磁盘且持有连接内计划；run 验证原计划后执行。计划最多16/连接、有效900秒，丢失/失效后刷新，不能替换任务。新增 optional_guidance_tools；required_guidance_tools 仍按 subset 检查。旧连接缺工具时沿已有同环境检查/重连指引。

## 四种生态的实际边界

| Provider | 检测与优先级 | Runtime 固定动作 |
| --- | --- | --- |
| Maven | pom.xml；平台 wrapper 优先，随后系统 mvn | `-o -B -q -DskipTests compile`；检测到 src/test Java 文件后 `-o -B -q -DfailIfNoTests=true test` |
| Gradle | build.gradle / build.gradle.kts；wrapper 优先 | `--offline --no-daemon --console=plain classes`；检测到 src/test Java/Kotlin/Groovy 文件后 test |
| Node/TS | package.json 中已有非空 scripts；pnpm-lock / yarn.lock / package-lock 绑定 manager | 依次 typecheck/test/lint/build，只运行存在的名字；npm offline+ignore-scripts（不执行 pre/post 脚本），pnpm/yarn offline；不调用 npx/corepack |
| Python | pyproject.toml / pytest.ini / setup.cfg + tests 目录 + 已安装 pytest | 当前非 frozen Python `-m pytest -q --no-header tests`；仅 requirements 文件不足以声称测试可用 |

不安装、下载、发布、部署或执行生产操作，不扩 Go/Rust/.NET 等生态。不接收模型提出的测试命令。Node script 内容是 UNTRUSTED_CODE；它不会变成 Runtime argv 或指令，运行自身仍可能执行任意代码，必须进入强制隔离。对 custom test layout、额外工具路径、大项目和依赖缺失保守返回不可用/部分证据，不伪造测试通过。

## 强制执行边界

**离线参数不等于网络隔离。** Maven plugin、wrapper、Gradle build、npm scripts、pytest conftest 都能执行代码。v0.1 无直接运行项目的 fallback。

Linux backend 必须同时具备已有 bubblewrap、user/network/PID 等 namespace 与可委派 cgroup v2。执行前写入并核对 pids.max=32、memory.max=1GiB、swap=0，要求 cgroup.kill；不能设置时不启动项目进程。子进程在 exec 前进入 cgroup；清理杀整个 cgroup。bubblewrap unshare-all/disable-userns/cap-drop/clearenv，网络 namespace 不连接宿主网络，不挂载宿主 HOME、/run、环境变量、凭据或完整 /etc。只读 /usr、运行库、JDK 公共配置，以及 Maven 本地 repository（不挂载 settings.xml）。Gradle 用户缓存/init scripts 不挂载；缺 distribution/dependencies 不下载。

源文件/配置在可丢弃临时 workspace projection 内只读；target/build/.gradle/dist/.pytest_cache 与 /tmp 是受 cgroup 内存预算限制的 tmpfs。验证产物不写回真实项目。临时源投影结束即删除，不进入持久化状态、审计、MCP 或模型；结果只保存 keyed hashes 和固定状态摘要。项目自定义输出目录若不可写会如实失败，不能放宽宿主文件系统。

Runtime 不调用 `shell=True`。固定 argv 交给隔离内已有工具；工具/wrapper 自身的 shell 或项目代码不获得宿主执行权限。workspace 必须精确匹配 MCP 绑定，绝对路径，拒绝 `..`、UNC、foreign workspace、link/junction/special file。snapshot 包含 ignored 文件，仅排除根 .git，最多200 files /400 entries /2MB total /512KB each；配置每个64KiB，工具身份读取最多32MB。超预算不运行。

每步60秒，整计划180秒，最多9步。stdout+stderr 合计64KiB，超过/超时/进程错误/信号/资源边界返回 INCONCLUSIVE；失败或未知后剩余步骤 NOT_RUN，不自动重试。只有 exit0 的已有命令得到该步骤 PASSED。Maven 无测试、Gradle test NO-SOURCE、pytest 无用例不标测试通过。原始输出从不返回/保存，只有 HMAC output_hash、固定 reason enum；无需猜测输出中的 Secret 是否全部可识别。

三层能力独立：**detection / planning 已实现且可用**，不需要 bubblewrap/cgroup；**execution contract / runner 已实现**，真实命令仅在 Runtime 判定安全前提满足时可运行；**hardened sandbox** 是执行前提，Linux backend 已实现、真实运行仍待验收，Windows/macOS 本轮没有 backend。缺少 sandbox 只让执行 fail closed / NOT_AVAILABLE，不把检测/计划能力标为不可用，也不降级到不受控 shell。

本机未发现 Maven/Gradle/bubblewrap/Docker，也没有可用 WSL 发行版入口；用户明确不提供或额外搭建环境、不安装/下载补齐。真实 Maven A/B execution、Desktop/host 功能闭环为 **PENDING_ENVIRONMENT_PREREQUISITES**，不是实现失败或 PASS。Linux hardened backend 实测独立 PENDING；接口、模拟 executor 与配置测试不能替代隔离实测。

## 独立结果与缓存

```json
{
  "security_verification": {"status": "SCANNER_VERIFIED_RESOLVED"},
  "functional_verification": {
    "status": "NOT_AVAILABLE",
    "coverage": "NONE",
    "steps": [],
    "baseline": "UNKNOWN",
    "regression_attribution": "NOT_PROVEN",
    "reason_code": "ENFORCED_LOCAL_SANDBOX_UNAVAILABLE",
    "reused": false
  },
  "overall_status": "SECURITY_VERIFIED_FUNCTION_UNKNOWN",
  "production_correctness": "UNKNOWN"
}
```

实际 run 不可用时 steps 列出计划动作及 NOT_RUN。Functional status 为 PASSED/FAILED/PARTIAL/NOT_AVAILABLE/INCONCLUSIVE；coverage 是实际通过的 BUILD_AND_TEST/TEST/TYPECHECK/BUILD 等，单独 build/lint 为 PARTIAL。

| Functional | Overall（安全已验证时） |
| --- | --- |
| PASSED | SECURITY_AND_FUNCTIONALLY_VERIFIED |
| PARTIAL | SECURITY_VERIFIED_FUNCTION_PARTIAL |
| FAILED | SECURITY_VERIFIED_FUNCTION_FAILED |
| NOT_AVAILABLE / INCONCLUSIVE | SECURITY_VERIFIED_FUNCTION_UNKNOWN |

没有可信 Runtime 修复前 baseline 导入入口，v0.1 一律 baseline=UNKNOWN / regression_attribution=NOT_PROVEN；不接受宿主 PASS 断言，不强制修复前再跑测试。失败不证明由修复造成，不恢复漏洞、不修改失败测试、不循环修复，action=REVIEW_REQUIRED：安全问题已消除，但功能验证失败，需要人工检查。

缓存身份包含 workspace、所有源码/配置 snapshot keyed digest、provider/verifier version、command ID、固定 argv/manager、已有 script 配置 hash、executable bytes hash、原 grant hash、isolation version。同 snapshot/plan 可复用（包括失败，避免重试循环）；源码/config 变化先拒绝旧计划，重新安全复核/prepare 后不得复用旧结果。计划与 run 都重检，执行前投影与执行后 live snapshot/安全 receipt 均须一致。

workspace OS 锁单飞。HMAC functional-cache 最多32条/262144bytes；仅身份/hash、provider/command_id、开始结束/耗时、exit/status、固定摘要和 output hash。无完整 stdout/stderr、环境、Secret、源码、用户 prompt 或 model output。没有改变 Raw、coverage、risk、family equivalence、修复 eligibility 或尝试预算。

## Disposable Maven 验收

已有 Runtime/MCP 与现有 Semgrep/Gitleaks 本地缓存是前提。脚本自动创建独立临时 Git Maven 项目并删除，**不操作 Jeepay 或用户 Desktop fixture**。

```powershell
Set-Location C:\Users\Administrator\Desktop\ai-security\Ai-security-check
& C:\Users\Administrator\AppData\Local\Programs\Python\Python313\python.exe scripts\functional_acceptance.py --output .security-runtime\functional-manual.json
```

本机预期 A/B/confirmed 都安全 RESOLVED、功能 NOT_AVAILABLE、overall UNKNOWN。退出0只表示安全/协议及 fail-closed 检查通过，**不是 Maven tests PASS**。

Windows native 对照：

```powershell
& C:\Users\Administrator\AppData\Local\Programs\Python\Python313\python.exe scripts\functional_acceptance.py --runtime .\dist\standalone\security-check\security-check.exe --output .security-runtime\functional-manual-native.json
```

在已经准备好离线工具与缓存且 cgroup 可委派的 Linux 环境中，使用其已有 Python/MCP/Runtime 与 Scanner 缓存执行：

```sh
SECURITY_RUNTIME_OFFLINE=1 python scripts/functional_acceptance.py --require-functional-pass --output functional-manual.json
```

strict 模式 Pending 退出2，禁止报告验收通过。A 使用原测试断言默认 hostname verifier，修复后 compile/test 需实际 PASSED、overall SECURITY_AND_FUNCTIONALLY_VERIFIED。B 的原测试依赖旧自定义 verifier，修复后应实际 TEST FAILED、安全仍 RESOLVED、overall SECURITY_VERIFIED_FUNCTION_FAILED，不自动恢复风险。第三条走用户批准链路（脚本模拟选择和宿主 edit）。普通 `mvn test` 直跑、安全隔离中的 Maven A/B、fresh Desktop 功能 handoff 是不同验收，当前前两类实测及 fresh Desktop 新能力均 PENDING。原 smart_auto/批准/拒绝 Desktop 三链路 PASS（USER_REPORTED）不受影响。

完整当前验收与 CI 见 [AQ](AI_TRIAGE_ACCEPTANCE.md#aq-functional-verification-v01)。Enterprise Gate、自动修失败测试、下一漏洞类型、其它 Host 和下一阶段保持 Planned。
