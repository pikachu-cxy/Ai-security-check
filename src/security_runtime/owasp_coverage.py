"""Versioned partial coverage ledger; metadata is never scan execution proof."""
from .rule_catalog import LANGUAGES, supports_language

CATEGORIES = [
    ('A01:2025','访问控制失效','对象/租户权限、网关和业务操作仍需逐端点审计。'),
    ('A02:2025','安全配置错误','只检查已建模设置；有效部署、解析器及错误处理配置仍需复核。'),
    ('A03:2025','软件供应链失效','依赖由独立引擎检查；完整图、构建插件与发布链未由 SAST 证明。'),
    ('A04:2025','密码学失效','TLS/密码哈希是局部检查；密钥生命周期、协议和随机性需审计。'),
    ('A05:2025','注入','仅建模部分来源/API/框架；跨函数、动态调用和编码上下文需追踪。'),
    ('A06:2025','不安全设计','通用规则不能证明业务状态机、竞态、滥用与设计安全。'),
    ('A07:2025','身份认证失效','JWT 局部检查不证明认证全流程、会话管理或生产身份配置安全。'),
    ('A08:2025','软件或数据完整性失效','反序列化局部检查不证明更新签名和全部信任边界。'),
    ('A09:2025','安全日志与告警失效','日志内容、告警联动和运行效果需要补充审计/运营证据。'),
    ('A10:2025','异常条件处理不当','异常路径、失败开放、资源耗尽和恢复行为需专项审计。'),
]
CATEGORY_MAP = {
    'path-traversal':'A01:2025','arbitrary-file-read':'A01:2025','arbitrary-file-write':'A01:2025',
    'ssrf':'A01:2025','csrf':'A01:2025','xxe':'A02:2025',
    'trust-all-tls':'A04:2025','tls-validation':'A04:2025','weak-password-hash':'A04:2025',
    'sql-injection':'A05:2025','command-injection':'A05:2025','code-injection':'A05:2025',
    'xss':'A05:2025','template-injection':'A05:2025',
    'security-misconfiguration':'A02:2025','authentication-bypass':'A07:2025',
    'unsafe-deserialization':'A08:2025','deserialization':'A08:2025',
}


def owasp_coverage(pack, selected=(), executed=()):
    selected = set(selected); executed = set(executed) & selected
    rows = []
    for category, title, limitation in CATEGORIES:
        matching = set()
        for rule in pack.catalog:
            capability = pack.program.capability(rule.rule_id) if pack.program else None
            mappings = capability.owasp_mapping if capability else ()
            if category in mappings or CATEGORY_MAP.get(rule.category) == category:
                matching.add(rule.rule_id)
        rows.append({'category':category,'title':title,'available_rule_count':len(matching),
            'selected_rule_ids':sorted(matching & selected),
            'executed_rule_ids':sorted(matching & executed),
            'scanner_pattern_coverage':'PARTIAL' if matching else 'NO_SAST_DETECTOR',
            'manual_review':'REQUIRED; NOT_ATTESTED_BY_RULE_EXECUTION','limitation':limitation})
    return {'edition':'2025','source':'https://top10.owasp.org/2025/',
            'scope':'SAST_PATTERN_SUBSETS_NOT_COMPLETE_TOP10','categories':rows,
            'whole_program_reachability':'NOT_IMPLEMENTED'}


def installed_inventory(pack):
    enabled = [r for r in pack.catalog if pack.program is None or pack.program.enabled(r.rule_id)]
    return {'status':'AVAILABLE','source':'CURRENT_INSTALLED_METADATA_NOT_SCAN_PROOF',
        'rule_pack_version':pack.descriptor.version,'rule_pack_checksum':pack.checksum,
        'available_sast_rules':len(pack.catalog),'default_enabled_sast_rules':len(enabled),
        'default_disabled_sast_rules':len(pack.catalog)-len(enabled),
        'per_language':{language:{'available':sum(supports_language(r,language) for r in pack.catalog),
            'default_enabled':sum(supports_language(r,language) for r in enabled)}
            for language in sorted(LANGUAGES-{'generic'})},
        'secret_rules':'SCANNER_OWNED_GITLEAKS_DETECTORS; NOT_COUNTED_AS_SAST',
        'owasp_top10':owasp_coverage(pack)}
