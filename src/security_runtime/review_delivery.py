"""Bounded post-Stop delivery. No scanner, worker or additional persistent cache."""
import hashlib
import json

from .performance_trace import review_mark


def json_bytes(value):
    return len(json.dumps(value, ensure_ascii=False, separators=(',', ':')).encode('utf-8'))


def response_budget(check):
    from .user_config import batch_config
    return batch_config(check)['development']['review_response_bytes']


def fit_review_page(page, positions, budget):
    """Enforce the logical JSON budget, including unusually long scanner fields."""
    # Leave room for the host session reference, closeout mode and timing.
    target = budget - 2048
    page['deferred_business_path_count'] = len(page['deferred_business_paths'])
    page['deferred_business_paths_truncated'] = False
    while json_bytes(page) > target:
        if page['evidence']:
            page['evidence'].pop()
            refs = {w['evidence_ref'] for w in page['evidence']}
            for candidate in page['candidates']:
                candidate['evidence_refs'] = [r for r in candidate['evidence_refs'] if r in refs]
                candidate['evidence_status'] = 'READY' if candidate['evidence_refs'] else 'MISSING'
        elif page['evidence_errors']:
            page['evidence_error_count'] = page.get('evidence_error_count', len(page['evidence_errors']))
            page['evidence_errors'].pop()
            page['evidence_errors_truncated'] = True
        elif page['deferred_business_paths']:
            page['deferred_business_paths'].pop()
            page['deferred_business_paths_truncated'] = True
        elif len(positions) > 1:
            index, kind, key = positions.pop()
            page['next_offset'] = index
            if kind == 'candidate':
                page['candidates'] = [c for c in page['candidates'] if c['id'] != key]
            else:
                page['business_paths'].remove(key)
        else:
            # A single scanner description may exceed a whole page. Preserve
            # identity/location and explicitly mark omitted advisory metadata.
            for candidate in page['candidates']:
                for key in ('description', 'rule_id', 'rule_severity', 'scanner_sources'):
                    if key in candidate:
                        candidate.pop(key)
                        candidate.setdefault('metadata_omitted', []).append(key)
            if json_bytes(page) > target:
                from .development_risks import require
                require(False, 'DEVELOPMENT_RISK_RESPONSE_ITEM_TOO_LARGE')
    page['delivery_metrics'].update(returned_windows=len(page['evidence']),
        evidence_bytes=sum(json_bytes(w) for w in page['evidence']))
    return page


def merge_windows(windows):
    """Merge overlap only when the union respects the existing 80-line boundary."""
    groups = {}
    for path, start, end, related in windows:
        groups.setdefault((path, related), []).append((start, end))
    grouped = []
    for (path, related), ranges in groups.items():
        merged = []
        for start, end in sorted(set(ranges)):
            if merged and start <= merged[-1][1] + 1 and end - merged[-1][0] < 80:
                merged[-1] = (merged[-1][0], max(end, merged[-1][1]))
            else:
                merged.append((start, end))
        grouped.append([(path, start, end, related) for start, end in merged])
    # Round-robin prevents one file consuming every other file's first window.
    return [group[i] for i in range(max(map(len, grouped), default=0))
            for group in grouped if i < len(group)]


def collect_evidence(service, candidates, paths, budget):
    review_mark('evidence_plan_start')
    windows = [(c['file_path'], c['line_start'], c['line_end'], False) for c in candidates]
    windows += [(p, 1, 80, False) for p in paths]
    core = merge_windows(windows)
    expanded = []
    for path, start, end, related in core:
        lo = max(1, start - 12, end - 79)
        expanded.append((path, lo if end - start < 80 else start,
                         min(lo + 79, end + 12) if end - start < 80 else end, related))
    # Merge the actual returned windows as well as the finding ranges. Two
    # non-adjacent findings can share the same expanded context.
    planned = merge_windows(expanded)
    required = {}
    for path, start, end, related in core:
        required.setdefault((path, related), []).append((start, end))
    review_mark('evidence_plan_done')
    evidence, errors = [], []
    used = 0
    for path, start, end, related in planned:
        if used >= budget:
            break
        if end - start >= 80:
            errors.append(dict(file_path=path, line_start=start, line_end=end,
                               reason_code='DEVELOPMENT_RISK_RANGE_INVALID'))
            continue
        # Context never displaces the actual candidate range. If context is too
        # large, retry only the required range, without changing validation.
        covered = [(lo, hi) for lo, hi in required[(path, related)] if start <= lo <= hi <= end]
        core_start = min((lo for lo, hi in covered), default=start)
        core_end = max((hi for lo, hi in covered), default=end)
        try:
            item = service.read(path, start, end, related=related)
            item = {k: item[k] for k in ('file_path', 'line_start', 'line_end', 'content', 'evidence_ref')}
            size = json_bytes(item)
            if size > budget - used and (core_start, core_end) != (start, end):
                item = service.read(path, core_start, core_end, related=related)
                item = {k: item[k] for k in ('file_path', 'line_start', 'line_end', 'content', 'evidence_ref')}
                size = json_bytes(item)
            if size <= budget - used:
                evidence.append(item)
                used += size
        except (ValueError, OSError) as error:
            errors.append(dict(file_path=path, line_start=start, line_end=end,
                               reason_code=getattr(error, 'reason_code', 'EVIDENCE_READ_FAILED')))
    return evidence, errors, dict(planned_windows=len(planned), returned_windows=len(evidence), evidence_bytes=used)


def report_page(page, check, root, offset=0, expected_digest=None):
    """Paginate complete, verified batch prose, not per-candidate summaries."""
    from .development_risks import require
    require(type(offset) is int and offset >= 0, 'DEVELOPMENT_RISK_PAGE_INVALID')
    if 'report_text' not in page:
        return page
    review_mark('report_pack_start')
    text = page['report_text']
    digest = hashlib.sha256(text.encode()).hexdigest()
    require(expected_digest is None or expected_digest == digest, 'DEVELOPMENT_RISK_VERSION_STALE')
    require(offset == 0 or expected_digest is not None, 'DEVELOPMENT_RISK_INPUT_INVALID')
    budget = response_budget(check)
    # Reserve envelope, timing, continuation, URL and summary fields. UTF-8
    # JSON escaping is counted, rather than estimating from candidate count.
    lo, hi = offset, len(text)
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if json_bytes(text[offset:mid]) <= budget - 8192:
            lo = mid
        else:
            hi = mid - 1
    end = lo
    following = end if end < len(text) else None
    action = None if following is None else dict(tool='get_development_risks', arguments=dict(
        workspace_path=str(root), check_ref=page['check_ref'], view='final_report',
        expected_seq=page['dirty_seq'], scan_id=page['scan_id'], offset=following, report_digest=digest))
    counts = {key: sum(r['decision'] == key for r in page['risks'])
              for key in ('CONFIRMED', 'DISMISSED', 'INCONCLUSIVE')}
    counts['duplicates'] = sum(bool((r.get('assessment') or {}).get('duplicate_of')) for r in page['risks'])
    counts['false_positives'] = counts['DISMISSED'] - counts['duplicates']
    result = dict(view='final_report', contract='development-final-report-v2',
        check_ref=page['check_ref'], dirty_seq=page['dirty_seq'], scan_id=page['scan_id'],
        host_review_completed=page['review_progress']['host_review_completed'],
        report_text=text[offset:end], report_digest=digest, report_fragment=following is not None or offset > 0,
        report_offset=offset, next_offset=following, next_action=action,
        total=page['total'], summary=counts, session_url=page.get('session_url'),
        gaps=page['gaps'], scope_unknown=page['scope_unknown'], response_budget_bytes=budget)
    review_mark('report_pack_done')
    return result


def pending_report_receipt(page, root):
    """A partial save stays bounded and cannot masquerade as a final report."""
    progress = page['review_progress']
    pending = {k: v for k, v in progress.items() if not isinstance(v, list)}
    pending.update(pending_scanner_count=len(progress['pending_scanner_ids']),
                   pending_business_count=len(progress['pending_business_paths']))
    result = {k: page[k] for k in ('check_ref', 'scan_id', 'dirty_seq', 'total', 'gaps',
              'scope_unknown', 'session_url', 'delivery_status', 'delivery_instruction') if k in page}
    waiting = page.get('delivery_status') == 'WAITING_FOR_STATIC_SCAN'
    result.update(view='review_receipt', contract='development-review-receipt-v2',
        candidates_ready=True, review_progress=pending, host_review_completed=False,
        next_offset=None, next_action=None if waiting else dict(tool='get_development_risks', arguments=dict(
            workspace_path=str(root), check_ref=page['check_ref'], view='review', offset=0,
            expected_seq=page['dirty_seq'], scan_id=page['scan_id'])))
    return result
