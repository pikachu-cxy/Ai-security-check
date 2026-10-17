"""Source identities captured with a scan, independent of reminder decisions.

Only hashes and bounded locator metadata are retained. A later read can relocate
the original occurrence without treating its old line number as current code.
"""
from __future__ import annotations

from .finding_quality import digest
from .local_evidence import evidence_locator
from .risk_disposition import issue_scope


def observation_signature(finding):
    locator = evidence_locator(finding)
    if not locator['file_sha256']:
        return None
    return digest([finding['category'], locator])


def capture_scopes(workspace, findings):
    """Best effort only: never discard a scan if its source is already gone.

    Matching the detector's captured hash also prevents binding working-tree
    code to a different staged/index snapshot. Dependencies have their own
    manifest/version identity adapter and do not use source statement scopes.
    """
    bindings = {}
    for finding in findings:
        if finding['category'] == 'dependency':
            continue
        try:
            signature = observation_signature(finding)
            if signature is None:
                continue
            scope = issue_scope(workspace, finding['file_path'], finding['line_start'],
                finding.get('line_end'), category=finding['category'],
                rule_id=finding.get('technical_details', {}).get('rule_id', ''))
            if scope['file_sha256'] == evidence_locator(finding)['file_sha256']:
                bindings[finding['id']] = dict(scope, observation_signature=signature)
        except (OSError, ValueError):
            continue
    return bindings
