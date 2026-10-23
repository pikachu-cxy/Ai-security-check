"""Bounded Gitleaks rule/file receipts, with no source, secret, or raw logs.

Gitleaks 8.30 SARIF lists configured detectors; trace records scope skips and
processed bytes. Neither one alone proves absence. Custom configuration and
legacy records lacking detector identity deliberately remain unconfirmed.
"""
import hashlib
import json
import re
from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path

CONTRACT = 'gitleaks-rule-file-v1'
_receipt = ContextVar('secret_execution_receipt', default=None)
_ID = re.compile(r'[A-Za-z0-9_.:/+@-]{1,200}')
_HASH = re.compile(r'[a-f0-9]{64}')


@contextmanager
def capture():
    receipt = {}
    token = _receipt.set(receipt)
    try:
        yield receipt
    finally:
        _receipt.reset(token)


def publish(receipt):
    target = _receipt.get()
    if target is not None:
        target.update(receipt)


def digest(path):
    from .hook_state import no_links
    no_links(Path(path).absolute())
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def text_file(path):
    from .hook_state import no_links
    no_links(Path(path).absolute())
    value = Path(path).read_bytes()
    if b'\x00' in value:
        return False
    try:
        value.decode('utf-8')
    except UnicodeError:
        return False
    return True


def rule_version(checksum, rule):
    return hashlib.sha256(f'{CONTRACT}|{checksum}|{rule}'.encode()).hexdigest()


def parse_report(data):
    if not isinstance(data, dict) or data.get('version') != '2.1.0' or len(data.get('runs', [])) != 1:
        raise ValueError('Secret scanner did not produce a supported scoped SARIF report')
    run = data['runs'][0]
    driver = run['tool']['driver']
    rules = driver.get('rules', [])
    if not isinstance(rules, list) or len(rules) > 1000:
        raise ValueError('Secret detector inventory exceeds supported bounds')
    ids = [r.get('id', '') for r in rules]
    if any(not isinstance(rid, str) or not _ID.fullmatch(rid) for rid in ids) or len(set(ids)) != len(ids):
        raise ValueError('Secret detector inventory is malformed')
    descriptions = {r['id']: r.get('shortDescription', {}).get('text', 'Potential secret') for r in rules}
    findings = []
    for item in run.get('results', []):
        rule = item['ruleId']
        if rule not in descriptions:
            raise ValueError('Secret result has no configured detector identity')
        for location in item['locations']:
            physical = location['physicalLocation']
            region = physical['region']
            # Gitleaks 8.30 places the actual match here. A missing snippet is
            # unavailable evidence, never the rule description or a guessed key.
            snippet = region.get('snippet', {})
            match = snippet.get('text', '') if isinstance(snippet, dict) else ''
            findings.append({'RuleID': rule, 'Description': descriptions[rule],
                'File': physical['artifactLocation']['uri'], 'StartLine': region['startLine'],
                'EndLine': region.get('endLine', region['startLine']),
                'Match': match if isinstance(match, str) else ''})
    return findings, tuple(sorted(ids)), driver.get('semanticVersion', ''), driver.get('name', '').lower()


def build_receipt(binary, version, rules, files, *, default_config, complete):
    if not default_config or version != '8.30.0':
        return {'contract': CONTRACT, 'status': 'UNPROVEN', 'reason': 'CONFIGURATION_OR_ENGINE_NOT_ATTESTED'}
    checksum = hashlib.sha256(json.dumps({'contract': CONTRACT, 'binary': digest(binary),
        'version': version, 'configuration': 'BUILTIN_DEFAULT', 'mode': 'dir',
        'decode_depth': 5, 'archive_depth': 0, 'ignore': 'NONE'}, sort_keys=True).encode()).hexdigest()
    return {'contract': CONTRACT, 'status': 'PROVEN' if complete else 'UNPROVEN',
        'reason': '' if complete else 'FILE_EXECUTION_OR_SKIP_NOT_PROVEN',
        'engine_version': version, 'configuration_checksum': checksum,
        'rule_ids': list(rules), 'scanned_files': dict(files) if complete else {}}


def trace_complete(log, sizes):
    # Logs stay invocation-local. Store no source-bearing trace fields, values,
    # arbitrary prose or paths extracted from engine output.
    if any(marker in log.lower() for marker in ('skipping', 'partial scan', 'permission denied')):
        return False
    if re.search(r'\b(?:ERR|FTL)\b', log):
        return False
    totals = re.findall(r'scanned ~([0-9]+) bytes', log)
    return (len(totals) == 1 and int(totals[0]) == sum(sizes.values()) and
            len(re.findall(r'\bTRC scanning path(?:\s|$)', log)) == len(sizes) and
            all(size > 0 for size in sizes.values()))


def trace_summary(log, sizes):
    skips = {'FILE': 0, 'RULE': 0, 'FINDING': 0, 'UNKNOWN': 0}
    reasons = {'GLOBAL_ALLOWLIST': 0, 'RULE_ALLOWLIST': 0, 'LOW_ENTROPY': 0,
               'INLINE_ALLOW': 0, 'FINGERPRINT': 0, 'BASELINE': 0, 'OTHER': 0}
    for line in log.splitlines():
        lower = line.lower()
        if 'skipping' not in lower:
            continue
        # Classify fixed upstream messages only. Never retain trace fields:
        # even redacted upstream trace can contain the matched secret.
        kind = ('FINDING' if 'skipping finding' in lower else
                'RULE' if 'skipping rule' in lower or 'skipping file: rule allowlist' in lower else
                'FILE' if 'skipping file' in lower or 'skipping fragment' in lower else 'UNKNOWN')
        skips[kind] += 1
        reason = next((name for marker, name in (
            ('global allowlist', 'GLOBAL_ALLOWLIST'), ('rule allowlist', 'RULE_ALLOWLIST'),
            ('low entropy', 'LOW_ENTROPY'), ('gitleaks:allow', 'INLINE_ALLOW'),
            ('fingerprint', 'FINGERPRINT'), ('baseline', 'BASELINE')) if marker in lower), 'OTHER')
        reasons[reason] += 1
    return {'expected_files': len(sizes), 'expected_bytes': sum(sizes.values()),
        'observed_paths': len(re.findall(r'\bTRC scanning path(?:\s|$)', log)),
        'observed_bytes': [int(n) for n in re.findall(r'scanned ~([0-9]+) bytes', log)],
        'skip_observed': 'skipping' in log.lower(),
        'skip_kinds': skips, 'skip_reasons': reasons,
        'error_observed': bool(re.search(r'\b(?:ERR|FTL)\b', log)),
        'partial_observed': 'partial scan' in log.lower()}


def identity(receipt, rule):
    checksum = receipt.get('configuration_checksum', '')
    if (not isinstance(checksum, str) or not _HASH.fullmatch(checksum) or
            receipt.get('engine_version') != '8.30.0' or rule not in receipt.get('rule_ids', [])):
        return {}
    return {'engine': 'gitleaks', 'rule_pack': 'gitleaks-default',
        'rule_pack_version': receipt['engine_version'], 'rule_pack_checksum': checksum,
        'rule_version': rule_version(checksum, rule)}


def covers(run, original, path, *, root=None):
    """Require original identity, successful fresh engine proof and exact file."""
    receipt = run.scanner_diagnostics.get('secret_coverage', {})
    if not isinstance(receipt, dict):
        return False
    if (run.scanner != 'gitleaks' or run.status != 'SUCCESS' or run.coverage_contract != 'FULL' or
            receipt.get('contract') != CONTRACT or receipt.get('status') != 'PROVEN' or
            receipt.get('engine_version') != run.version):
        return False
    rule = original.get('rule_id', '')
    expected = identity(receipt, rule)
    if not expected or any(original.get(k) != v for k, v in expected.items() if k not in {'rule_pack', 'rule_pack_version'}):
        return False
    revision = receipt.get('scanned_files', {}).get(path)
    if not isinstance(revision, str) or not _HASH.fullmatch(revision):
        return False
    if root is not None:
        try:
            if digest(Path(root) / path) != revision:
                return False
        except (OSError, ValueError):
            return False
    return True
