# Extending AI Security Runtime

## Add a scanner

Implement the `ScannerAdapter` protocol in `scanners.py` (or a new scanner module): a name, `supports(TargetProfile, ScanContext)`, and `scan(ScanContext, FindingNormalizer)`. Register it in `ScannerRegistry`. Declare scope through `supports`, so QUICK avoids a full scan. Normalize each result to a Finding, report unavailable/failed/timeout with `ScannerRun`, and add a real integration test using the installed scanner. A MobSF adapter would be registered only for `MOBILE_APP` targets.

## Add an integration

Call `SecurityRuntime.scan`, or invoke `security-check scan` from an external tool. A Cursor or Claude hook adapter should translate its event to a mode and path; it must not parse scanner output or compute risk. Use MCP for agent initiated scans and fix/verify flows.

## Add a target type

Extend `TargetType`, add a profiler that fills `TargetProfile`, and add adapters whose `supports` selects the new type. An `AI_SKILL` profiler would identify SKILL.md and tool permissions, then a Skill scanner would emit the same Finding contract. CLI, MCP, storage, and RiskEngine continue to use the shared result model.

## Privacy boundary

Never send repository contents to an external service. If AI enhancement is added, build minimal context with `ContextProvider`, redact it, cap length, and pass only that to `AIProvider`. Keep cloud sync disabled unless explicitly enabled by the user.
