"""Compact MCP projections; never change saved risks or review requirements."""
from copy import deepcopy
from pydantic import BaseModel, ConfigDict, Field


class EvidenceWindow(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    file_path: str
    start_line: int = Field(default=1, ge=1)
    end_line: int = Field(default=80, ge=1)
    related: bool = False


def read_contexts(service, windows):
    from .development_risks import require
    check = service.current_check()
    version = (check['dirty_seq'], check.get('scan_id'))
    evidence, seen = [], set()
    for window in windows:
        key = (window.file_path, window.start_line, window.end_line, window.related)
        if key in seen:
            continue
        seen.add(key)
        # Sequential reads preserve the existing evidence transaction semantics.
        item = service.read(window.file_path, window.start_line, window.end_line,
                            related=window.related)
        require(item['dirty_seq'] == version[0], 'DEVELOPMENT_RISK_VERSION_STALE')
        evidence.append(item)
    current = service.current_check()
    require((current['dirty_seq'], current.get('scan_id')) == version,
            'DEVELOPMENT_RISK_VERSION_STALE')
    return dict(dirty_seq=version[0], scan_id=version[1], evidence=evidence,
                scanner_run=False, trust='UNTRUSTED_SOURCE', review_saved=False)


def risk_summary(result):
    result = deepcopy(result)
    for item in result.get('risks', []):
        assessment = item.get('assessment')
        if assessment:
            # The current finding is already present at item.finding.
            assessment.pop('finding', None)
            assessment.pop('source_hashes', None)
    result['view'] = 'summary'
    result['detail_access'] = dict(tool='get_development_risks',
                                 arguments=dict(check_ref=result['check_ref'], view='full'))
    return result


def review_receipt(result):
    # A preview cannot replace the required post-submit read. Return only the
    # saved version/progress and its issued next action, not the same risks twice.
    keys = ('contract', 'check_ref', 'scan_id', 'dirty_seq', 'review_progress',
            'next_action', 'review_version_count', 'scanner_run', 'source_freshness',
            'repair_authorized', 'decision_policy')
    receipt = {key: result[key] for key in keys if key in result}
    receipt.update(review_saved=True, reread_required=True, host_report_submitted=False)
    return receipt
