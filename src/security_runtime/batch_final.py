"""Final-version accounting for opt-in host reviews; no model or scanner calls."""
from __future__ import annotations

from .task_security import _clean

CHECKS = ('authorization', 'data_flow', 'configuration', 'cross_batch_calls')


def candidate_index(record):
    """Include historical/partial candidates as navigation, never current proof."""
    return [dict(batch_ref=batch['batch_ref'], candidate_id=finding['id'],
                 title=finding['title'][:120], file_path=finding['file_path'])
            for batch in record['batch_state']['batches']
            for finding in (batch.get('review') or {}).get('findings', [])]


def integration_contract(snapshot_id):
    return dict(snapshot_id=snapshot_id,
        required_fields=['snapshot_id', 'batch_refs', 'reviewed_paths', 'evidence_refs',
                         'checks', 'candidate_dispositions', 'limitations'],
        checks={key: 'bounded explanation, including why not applicable' for key in CHECKS},
        candidate_dispositions='Each batch candidate: batch_ref,candidate_id,outcome(PRESENT/EXCLUDED/UNKNOWN),evidence_refs,reason; PRESENT also requires primary_evidence of a final finding.',
        evidence='Current final-session evidence only. Old batch ids are navigation, never current proof.',
        trust='HOST_REPORTED_REASONING; STRUCTURE_AND_VERSION_VALIDATION_ONLY')


def close_batch_inputs(record):
    state = record.get('batch_state')
    if not state:
        return
    state['finalizing'] = True
    for batch in state['batches']:
        if batch['status'] == 'RUNNING':
            batch['status'] = 'CANCELLED_AT_FINAL'
    if state.get('pending'):
        state['pending']['status'] = 'CANCELLED_AT_FINAL'


def validate_integration(record, report, accepted):
    """An input/coverage receipt, not proof that reasoning or an exploit ran."""
    if not record.get('batch_state'):
        if report is not None:
            raise ValueError('Integration review requires an enabled batch task')
        return None, []
    if report is None:
        return None, ['最终跨批次关联核查尚未提交；批次完成不能替代最终版本核查。']
    keys = {'snapshot_id', 'batch_refs', 'reviewed_paths', 'evidence_refs', 'checks',
            'candidate_dispositions', 'limitations'}
    if not isinstance(report, dict) or set(report) != keys:
        raise ValueError('Use the final integration review contract')
    coverage = record['packet']['batch_review']
    if report['snapshot_id'] != coverage['snapshot_id']:
        raise ValueError('Final integration snapshot changed')
    refs, paths, evidence = report['batch_refs'], report['reviewed_paths'], report['evidence_refs']
    if (not isinstance(refs, list) or len(refs) > 8 or any(not isinstance(v,str) for v in refs)
            or len(set(refs)) != len(refs)):
        raise ValueError('Invalid reused batches')
    candidates = {b['batch_ref']: b for b in coverage['reusable_candidates']}
    if any(ref not in candidates for ref in refs):
        raise ValueError('A stale or unfinished batch cannot be reused')
    required = set(coverage['review_scope'])
    if (not isinstance(paths,list) or len(paths)>1000 or any(not isinstance(p,str) for p in paths)
            or len(set(paths)) != len(paths) or not set(paths) <= required):
        raise ValueError('Invalid final reviewed scope')
    if (not isinstance(evidence,list) or len(evidence)>40 or any(
            not isinstance(e,str) or e not in record['evidence'] for e in evidence)):
        raise ValueError('Final integration needs current issued evidence')
    deleted = {c['path'] for c in record['changes'] if c['change'] == 'DELETED'}
    def current_evidence(ref):
        item = record['evidence'][ref]
        return item['location_version'] == 'CURRENT_TASK_END' or (
            item['location_version'] == 'BEFORE_DELETION' and item['path'] in deleted)
    if any(not current_evidence(ref) for ref in evidence):
        raise ValueError('Final integration cannot use historical task preimages')
    checks = report['checks']
    if not isinstance(checks,dict) or set(checks) != set(CHECKS):
        raise ValueError('Explain the final cross-batch checks')
    clean_checks = {key:_clean(value,500) for key,value in checks.items()}
    limits = report['limitations']
    if not isinstance(limits,list) or len(limits)>30:
        raise ValueError('Invalid integration limitations')
    gaps = [_clean(value,500) for value in limits]
    current_paths = {record['evidence'][ref]['path'] for ref in evidence
                     if record['evidence'][ref]['location_version'] in
                     {'CURRENT_TASK_END', 'BEFORE_DELETION'}}
    reusable_paths = {entry['path'] for ref in refs for entry in candidates[ref]['review_scope']}
    missing = required - set(paths) | (required - current_paths - reusable_paths)
    if missing:
        gaps.append('最终版本尚未取得完整审查覆盖：'+'、'.join(sorted(missing)[:20]))
    if required and not evidence:
        gaps.append('最终关联核查缺少当前版本源码证据。')
    all_findings = {(b['batch_ref'], finding['id']): finding
                    for b in record['batch_state']['batches']
                    for finding in (b.get('review') or {}).get('findings', [])}
    dispositions = report['candidate_dispositions']
    if not isinstance(dispositions,list) or len(dispositions)>80:
        raise ValueError('Invalid batch candidate dispositions')
    seen, cleaned = set(), []
    for item in dispositions:
        base_keys = {'batch_ref','candidate_id','outcome','evidence_refs','reason'}
        if not isinstance(item,dict) or not base_keys <= set(item) <= base_keys|{'primary_evidence'}:
            raise ValueError('Use the batch candidate disposition contract')
        key = (item['batch_ref'],item['candidate_id'])
        if key not in all_findings or key in seen or item['outcome'] not in {'PRESENT','EXCLUDED','UNKNOWN'}:
            raise ValueError('Invalid or duplicate batch candidate outcome')
        seen.add(key)
        proof = item['evidence_refs']
        if not isinstance(proof,list) or not 1 <= len(proof) <= 10 or any(
                not isinstance(e,str) or e not in record['evidence'] for e in proof):
            raise ValueError('Candidate outcomes require final-session evidence')
        if any(not current_evidence(ref) for ref in proof):
            raise ValueError('Historical task preimages cannot exclude a current candidate')
        reason = _clean(item['reason'],800)
        finding = all_findings[key]
        required_paths = {finding['file_path']} | {
            location['path'] for location in finding.get('evidence_locations', [])}
        proof_paths = {record['evidence'][e]['path'] for e in proof}
        if item['outcome'] == 'UNKNOWN' or not required_paths <= proof_paths:
            gaps.append('批次候选仍待最终核查：'+finding['title'])
        if item['outcome'] == 'PRESENT' and not any(
                f.get('primary_evidence') == item.get('primary_evidence') for f in accepted):
            raise ValueError('Present batch candidate must map to a submitted final finding')
        cleaned.append({**item, 'reason':reason})
    if set(all_findings)-seen:
        gaps.append('部分批次候选没有最终处理结论，不能因代码变化或零发现自动关闭。')
    return dict(snapshot_id=report['snapshot_id'], batch_refs=refs, reviewed_paths=paths,
        evidence_refs=evidence, checks=clean_checks, candidate_dispositions=cleaned,
        limitations=gaps, validation='HOST_REPORTED_NOT_SCANNER_PROOF'), gaps
