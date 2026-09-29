# Extending AI Security Runtime

## Add a scanner

Publish a Python package with an `ai_security_runtime.scanners` entry point returning a `ScannerAdapter`. Include `ScannerPluginMetadata` with a unique scanner ID, display name, versions, capabilities, supported languages and ecosystems, and required engine IDs. Implement `required_engines`, `supports`, `scan`, and `normalize`. Convert raw output to the shared `Finding` model. The runtime, CLI, MCP server, risk engine, and SQLite flow discover it without source changes. See `tests/test_plugin_e2e.py`.

## Add an engine

Provide a pinned `ToolManifest` through `ai_security_runtime.tool_manifests`, or a `PythonEngineSpec` through `ai_security_runtime.python_engines`. Register complete `LicenseMetadata` at the same time. `ToolManager` rejects automatic installation for restricted or unknown licenses. Binary releases need an official HTTPS asset and SHA256 digest. Python package engines use an isolated managed venv. See `tests/test_python_engine.py`.

Before distribution, run `security-check licenses --check-distribution`. Review obligations for weak copyleft components before packaging. Proprietary tools such as CodeQL must be supplied by a user through an explicit path and must not be auto-downloaded.

## Add a rule pack

`RulePackManager` is independent from engine installation. The bundled `ai-security-core` pack is versioned separately from Runtime and uses the `ai-security.*` rule namespace. Every first-party rule declares publisher, pack, version, confidence, license, references, and provenance. Rules derived from other work require source-license review and are rejected by the bundled validator. `PatternSASTScanner` receives an `SASTEngineProvider` and the resolved local rule pack. The current subclass uses Semgrep; a future Opengrep subclass can use the same pack.

`security-check scan --rules <directory>` executes local user-provided rules without copying or redistributing them. Default scans do not fetch community or registry rules.

## Add an integration

Call `SecurityRuntime.scan`, or invoke `security-check scan` from an external tool. A Cursor or Claude hook adapter should translate its event to a mode and path; it must not parse scanner output or compute risk. Use MCP for agent initiated scans and fix/verify flows.

## Add a target type

Extend `TargetType`, add a profiler that fills `TargetProfile`, and add adapters whose `supports` selects the new type. An `AI_SKILL` profiler would identify SKILL.md and tool permissions, then a Skill scanner would emit the same Finding contract. CLI, MCP, storage, and RiskEngine continue to use the shared result model.

## Privacy boundary

Never send repository contents to an external service. If AI enhancement is added, build minimal context with `ContextProvider`, redact it, cap length, and pass only that to `AIProvider`. Keep cloud sync disabled unless explicitly enabled by the user.
