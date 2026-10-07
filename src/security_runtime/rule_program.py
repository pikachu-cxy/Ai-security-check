"""Capability identity and evidence policy above scanner-owned execution rules.

The manifest contains no user source or credentials. It does not grant fixes.
Existing remediation policies remain the authority for fix eligibility.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import json
import re

MATURITIES = ('EXPERIMENTAL', 'VALIDATED', 'CORE', 'AUTO_FIX_ELIGIBLE')
ENGINES = {'semgrep', 'gitleaks'}
MAX_MANIFEST = 262144
CAPABILITY_FIELDS = {'capability_id', 'title', 'language', 'category', 'severity', 'cwe',
    'owasp_mapping', 'maturity', 'scanner_engine', 'underlying_rule_ids', 'frameworks',
    'evidence_contract', 'remediation_mode', 'auto_fix_eligible', 'default_enabled',
    'test_corpus', 'family_anchor'}
EVIDENCE_FIELDS = {'basis', 'source', 'sink', 'dataflow_scope', 'location',
    'rule_identity', 'confidence', 'limitations'}


@dataclass(frozen=True)
class DetectionCapability:
    capability_id: str
    title: str
    language: str
    category: str
    severity: str
    cwe: tuple[str, ...]
    owasp_mapping: tuple[str, ...]
    maturity: str
    scanner_engine: str
    underlying_rule_ids: tuple[str, ...]
    frameworks: tuple[str, ...]
    evidence_contract: dict
    remediation_mode: str
    auto_fix_eligible: bool
    default_enabled: bool
    test_corpus: dict
    family_anchor: str


@dataclass(frozen=True)
class RuleProgram:
    version: str
    capabilities: tuple[DetectionCapability, ...]
    legacy_rules: tuple[dict, ...]

    def capability(self, rule_id, engine='semgrep'):
        return next((c for c in self.capabilities if c.scanner_engine == engine and
            (rule_id in c.underlying_rule_ids or c.underlying_rule_ids == ('gitleaks:*',))), None)

    def enabled(self, rule_id):
        capability = self.capability(rule_id)
        if capability is not None:
            return capability.default_enabled and capability.maturity != 'EXPERIMENTAL'
        return any(r['rule_id'] == rule_id and r['default_enabled'] and
                   r['maturity'] != 'EXPERIMENTAL' for r in self.legacy_rules)

    def family_rules(self, rule_id):
        capability = next((c for c in self.capabilities if rule_id == c.family_anchor or
            rule_id in c.underlying_rule_ids), None)
        return capability.underlying_rule_ids if capability and capability.scanner_engine == 'semgrep' else (rule_id,)


def _strings(value, *, allow_empty=False):
    return isinstance(value, list) and (allow_empty or bool(value)) and len(value) <= 100 and all(
        isinstance(v, str) and 0 < len(v) <= 500 for v in value) and len(value) == len(set(value))


def validate_manifest(data, catalog):
    if not isinstance(data, dict) or set(data) != {'schema_version','program_id','version',
            'rule_pack','capabilities','legacy_rules','overlap_policy','profiles'}:
        raise ValueError('Rule Program manifest schema invalid')
    if data['schema_version'] != 'rule-program-v1' or data['rule_pack'] != 'ai-security-core' or not re.fullmatch(r'\d+\.\d+\.\d+', str(data['version'])):
        raise ValueError('Rule Program identity invalid')
    definitions = {r.rule_id:r for r in catalog}
    capabilities = []; ids = set(); owned = set(); anchors = set()
    if not isinstance(data['capabilities'], list) or not 1 <= len(data['capabilities']) <= 100:
        raise ValueError('Rule Program capability budget invalid')
    for row in data['capabilities']:
        if not isinstance(row, dict) or set(row) != CAPABILITY_FIELDS:
            raise ValueError('Capability schema invalid')
        cid = row['capability_id']
        if not isinstance(cid, str) or not re.fullmatch(r'[A-Z][A-Z0-9_]{1,99}', cid) or cid in ids:
            raise ValueError('Duplicate or invalid capability ID')
        ids.add(cid)
        if row['maturity'] not in MATURITIES or row['scanner_engine'] not in ENGINES:
            raise ValueError('Capability maturity or engine invalid')
        if row['language'] not in {'java','any','python','javascript','typescript','go','php'} or row['severity'] not in {'LOW','MEDIUM','HIGH','CRITICAL'}:
            raise ValueError('Capability language or severity invalid')
        for name in ('title','category','family_anchor','remediation_mode'):
            if not isinstance(row[name], str) or not 0 < len(row[name]) <= 200:
                raise ValueError('Capability text invalid')
        for name in ('underlying_rule_ids','frameworks','cwe','owasp_mapping'):
            if not _strings(row[name], allow_empty=name == 'owasp_mapping'):
                raise ValueError('Capability list invalid')
        if any(not re.fullmatch(r'CWE-\d+', v) for v in row['cwe']):
            raise ValueError('Capability CWE invalid')
        if type(row['auto_fix_eligible']) is not bool or type(row['default_enabled']) is not bool:
            raise ValueError('Capability flags invalid')
        if row['maturity'] == 'EXPERIMENTAL' and row['default_enabled']:
            raise ValueError('Experimental capability cannot enter default protection')
        # A manifest cannot graduate a second automatic fixer by assertion.
        if row['auto_fix_eligible'] and (cid != 'JAVA_TLS_HOSTNAME_VERIFICATION_DISABLED' or
                row['maturity'] not in {'CORE','AUTO_FIX_ELIGIBLE'} or row['underlying_rule_ids'] != ['ai-security.java.trust-all-hostname']):
            raise ValueError('Automatic fix requires existing guarded TLS graduation')
        if row['maturity'] == 'AUTO_FIX_ELIGIBLE' and not row['auto_fix_eligible']:
            raise ValueError('Automatic fix maturity requires separate eligibility')
        evidence = row['evidence_contract']
        if not isinstance(evidence, dict) or set(evidence) != EVIDENCE_FIELDS or evidence['confidence'] not in {'LOW','MEDIUM','HIGH'} or not _strings(evidence['limitations']):
            raise ValueError('Capability evidence contract invalid')
        if any(not isinstance(evidence[k], str) or not 0 < len(evidence[k]) <= 500 for k in EVIDENCE_FIELDS - {'limitations'}):
            raise ValueError('Capability evidence text invalid')
        corpus = row['test_corpus']
        if not isinstance(corpus, dict) or set(corpus) != {'manifest','kind'} or corpus['kind'] not in {'SYNTHETIC','OSS','INTERNAL'} or corpus['manifest'] != 'tests/rule_program/corpus.json':
            raise ValueError('Capability corpus contract invalid')
        if row['family_anchor'] in anchors:
            raise ValueError('Duplicate capability family anchor')
        anchors.add(row['family_anchor'])
        for rid in row['underlying_rule_ids']:
            if rid in owned:
                raise ValueError('Underlying rule ownership is duplicated')
            owned.add(rid)
            if row['scanner_engine'] == 'gitleaks':
                if cid != 'HARDCODED_SECRET' or rid != 'gitleaks:*' or row['language'] != 'any':
                    raise ValueError('Secret detectors must remain scanner-owned')
            elif rid not in definitions or definitions[rid].language != row['language']:
                raise ValueError('Underlying rule ownership or language invalid')
        converted = dict(row)
        for name in ('underlying_rule_ids','frameworks','cwe','owasp_mapping'):
            converted[name] = tuple(converted[name])
        capabilities.append(DetectionCapability(**converted))
    legacy = data['legacy_rules']
    if not isinstance(legacy, list) or len(legacy) > 1000:
        raise ValueError('Legacy rule budget invalid')
    for row in legacy:
        if not isinstance(row, dict) or set(row) != {'rule_id','maturity','default_enabled','test_corpus'} or row['maturity'] not in MATURITIES or type(row['default_enabled']) is not bool:
            raise ValueError('Legacy rule declaration invalid')
        rid = row['rule_id']
        if rid not in definitions or rid in owned or row['test_corpus'] != definitions[rid].fixture:
            raise ValueError('Underlying rule ownership invalid')
        if row['maturity'] == 'EXPERIMENTAL' and row['default_enabled']:
            raise ValueError('Experimental legacy rule cannot enter default protection')
        owned.add(rid)
    if owned - {'gitleaks:*'} != set(definitions):
        raise ValueError('Every execution rule needs explicit capability or legacy ownership')
    if data['overlap_policy'] != {'primary':['JAVA_ARBITRARY_FILE_READ','JAVA_ARBITRARY_FILE_WRITE'],
            'secondary':'JAVA_PATH_TRAVERSAL','match':'SAME_FILE_AND_SINK_RANGE','keep_rule_evidence':True}:
        raise ValueError('Unsupported capability overlap policy')
    profiles = data['profiles']
    expected_core = [c.capability_id for c in capabilities if c.language in {'java','any'} and c.maturity in {'CORE','AUTO_FIX_ELIGIBLE'}]
    expected_validated = [c.capability_id for c in capabilities if c.language == 'java' and c.maturity == 'VALIDATED']
    if profiles != {'java_core_pack_v1':expected_core,'validated_java_pack_v1':expected_validated}:
        raise ValueError('Rule Program profiles must keep maturity tiers separate')
    return RuleProgram(data['version'], tuple(capabilities), tuple(legacy))


def load_program(path, catalog):
    file = Path(path) / 'capabilities.json'
    if not file.is_file() or file.is_symlink() or file.is_junction() or file.stat().st_size > MAX_MANIFEST:
        raise ValueError('Rule Program manifest missing or unsafe')
    return validate_manifest(json.loads(file.read_text(encoding='utf-8')), catalog)


def annotate(finding, capability, program_version, record=None):
    """Keep underlying engine identity and attach bounded semantic evidence."""
    finding.title = capability.title
    finding.category = capability.category
    if finding.category not in {'secret','command-injection'}:
        finding.plain_title = capability.title
    evidence = dict(capability.evidence_contract)
    if record is not None and record.mode == 'search' and evidence['basis'] == 'ENGINE_TAINT_MATCH':
        evidence.update(basis='STRUCTURAL_MATCH',dataflow_scope='STRUCTURAL',
            source='DYNAMIC_SQL_INTERPOLATION; PARAMETER_TRUST_NOT_ESTABLISHED')
    finding.technical_details.update(capability_id=capability.capability_id,
        capability_maturity=capability.maturity, capability_program_version=program_version,
        capability_family_anchor=capability.family_anchor,
        auto_fix_eligible=capability.auto_fix_eligible,
        detection_evidence={**evidence,
            'location':{'line_start':finding.line_start,'line_end':finding.line_end},
            'rule_identity':finding.technical_details['rule_id'],
            'source_location':'NOT_EXPORTED', 'exploitability':'NOT_ESTABLISHED'})


def aggregate(findings):
    """Read/write is primary at the same sink; traversal remains related evidence.

    Keep all distinct sink coordinates, and keep traversal-only occurrences.
    This is normalization, not a new Finding or authorization system.
    """
    primary = {}
    for finding in findings:
        if finding.technical_details.get('capability_id') in {'JAVA_ARBITRARY_FILE_READ','JAVA_ARBITRARY_FILE_WRITE'}:
            primary[(finding.file_path,finding.line_start,finding.line_end)] = finding
    result = []
    for finding in findings:
        current = primary.get((finding.file_path,finding.line_start,finding.line_end))
        if current is not None and finding.technical_details.get('capability_id') == 'JAVA_PATH_TRAVERSAL':
            current.technical_details['related_capabilities'] = ['JAVA_PATH_TRAVERSAL']
            current.technical_details['supporting_rule_ids'] = [finding.technical_details['rule_id']]
        else:
            result.append(finding)
    return result
