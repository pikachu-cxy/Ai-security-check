"""Additive bounded views; the legacy complete interfaces remain available."""


def page_bounds(view, offset, limit, *, evidence=False):
    if view not in {'full', 'page', 'summary'}:
        raise ValueError('view must be full, page or summary')
    maximum = 5 if evidence else 50
    if type(offset) is not int or not 0 <= offset <= 1_000_000:
        raise ValueError('offset must be between 0 and 1000000')
    if limit is not None and (type(limit) is not int or not 1 <= limit <= maximum):
        raise ValueError(f'limit must be between 1 and {maximum}')
    if view == 'full' and (offset or limit is not None):
        raise ValueError('Pagination requires view=page or summary')
    return min(20, maximum) if limit is None else limit


def finding_summary(item):
    quality = item.get('quality') or {}
    triage = item.get('triage') or {}
    return {key: item.get(key) for key in ('id', 'category', 'severity', 'confidence',
        'file_path', 'line_start', 'line_end', 'plain_title', 'triage_status')} | {
        'scanner_sources':quality.get('scanner', []),
        'rule_id': quality.get('rule_id', ''),
        'quality_review': {key: quality.get(key) for key in
            ('finding_id', 'triage_status', 'triage_source')},
        'ai_triage': {key: triage.get(key) for key in ('verdict', 'confidence', 'priority')},
        **({'false_positive_review': {key: item['false_positive_review'].get(key) for key in
            ('state', 'folded', 'agent_review_current', 'message', 'assessment_source',
             'handling_status', 'handling_label', 'handling_source', 'reminder_suppressed',
             'reassessment_required', 'disposition', 'verification', 'verification_read_status')}}
            if 'false_positive_review' in item else {}),
        **({'local_evidence': item['local_evidence']} if 'local_evidence' in item else {}),
        **({'review_continuation': item['review_continuation']} if 'review_continuation' in item else {})}


def paged(items, total, offset, limit, *, tool, arguments):
    next_offset = offset + len(items)
    continuation = ({'tool': tool, 'arguments': {**arguments, 'offset': next_offset, 'limit': limit}}
                    if next_offset < total else None)
    return {'items': items, 'total': total, 'offset': offset, 'limit': limit,
            'continuation': continuation,
            'complete_results': {'tool': tool, 'arguments': {**arguments, 'view': 'full'}}}
