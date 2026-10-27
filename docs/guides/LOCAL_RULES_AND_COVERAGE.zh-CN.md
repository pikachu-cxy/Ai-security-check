# 内置规则与本地规则

当前源码默认使用 OpenGrep 1.32.0 与固定版本的 opengrep-rules。规则原文位于 `src/security_runtime/rules`，来源、版本和逐文件校验记录位于 `src/security_runtime/opengrep_rules.json`。

```powershell
security-check scan --path C:\projects\my-app --rules C:\security\my-rules
```

`--rules` 替换本次扫描的默认 YAML 规则集，不自动合并；用户规则仍由 OpenGrep 执行，保留原 ID。请在自定义目录内保证 ID 唯一。上游目录含跨文件重复 ID，因此不要直接把整个上游目录复制为用户规则包；默认内置加载会根据路径限定 ID。自定义规则仍由用户维护，不添加在线更新服务。

```yaml
rules:
  - id: company.php.forbidden-debug
    languages: [php]
    severity: WARNING
    message: Remove debug_dump before deployment.
    pattern: debug_dump(...)
```

规则配置变化会改变扫描绑定的校验值；规则语法错误会报错，不静默忽略。`--rules` 不替换独立原生辅助分析器。历史自研 YAML 规则和专用基准不再代表默认规则集。

维护者从固定提交导入上游规则时使用 `scripts/vendor_opengrep_rules.py`，导入前备份现有目录。导入保留上游 YAML 和 LICENSE，不复制仓库 CI 与测试样本。可使用 OpenGrep 的 `scan --validate --config <目录>` 检查用户规则语法。实际产品覆盖以选中及执行的规则、文件和解析结果为准。
