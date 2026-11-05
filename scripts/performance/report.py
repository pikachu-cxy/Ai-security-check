"""Summarize one capture without adding nested or parallel span durations."""
import argparse
from collections import defaultdict
import json
from pathlib import Path
import statistics


def report(root):
    manifest = json.loads((root/'run.json').read_text())
    starts, ends = {}, {}
    rejected = 0
    batches = defaultdict(list)
    reviews = defaultdict(list)
    files = sorted(root.glob('events-*.jsonl'))
    if len(files) > 256:
        raise ValueError('Too many process logs')
    capped = []
    for path in files:
        if path.is_symlink() or path.stat().st_size > 8_000_000:
            raise ValueError('Invalid or oversized timing log')
        if path.stat().st_size > 7_990_000:
            capped.append(path.name)
        for line in path.read_text().splitlines():
            try:
                row = json.loads(line)
                if row['run'] != manifest['run'] or row['event'] not in {'start', 'end', 'queue', 'review'}:
                    raise ValueError('Unrelated event')
                if row['event'] == 'queue':
                    batches[row['batch']].append(row)
                    continue
                if row['event'] == 'review':
                    reviews[row['batch']].append(row)
                    continue
                key = (row['process'], row['span'])
                (starts if row['event'] == 'start' else ends)[key] = row
            except (ValueError, KeyError):
                rejected += 1
    groups = defaultdict(list)
    raised = defaultdict(int)
    mcp_intervals = []
    for key, end in ends.items():
        if key not in starts:
            continue
        start = starts[key]
        elapsed = (end['monotonic_ns']-start['monotonic_ns'])/1e6
        if elapsed < 0 or start['phase'] != end['phase']:
            rejected += 1
            continue
        groups[start['phase']].append(elapsed)
        if start['phase'].startswith('mcp.'):
            mcp_intervals.append((start['monotonic_ns'], end['monotonic_ns']))
        raised[start['phase']] += end['status'] == 'raised'
    rows = []
    for phase, values in sorted(groups.items()):
        ordered = sorted(values)
        # Do not imply a stable tail percentile from a handful of samples.
        p95 = ordered[__import__('math').ceil(len(values)*.95)-1] if len(values) >= 20 else None
        rows.append(dict(phase=phase, count=len(values), median_ms=round(statistics.median(values), 3),
                         max_ms=round(max(values), 3), p95_ms=p95, raised=raised[phase]))
    queue = []
    for batch, events in batches.items():
        submitted = [r['monotonic_ns'] for r in events if r['action']=='submitted']
        attempts = [r['monotonic_ns'] for r in events if r['action']=='attempt']
        wait = (min(attempts)-min(submitted))/1e6 if submitted and attempts else None
        queue.append(dict(batch=batch, attempts=len(attempts),
                          submit_to_first_attempt_ms=wait if wait is not None and wait >= 0 else None))
    present = set(groups)
    review_windows = []
    for batch, events in reviews.items():
        reads = [r['monotonic_ns'] for r in events if r['action'] == 'evidence_read']
        complete = [r['monotonic_ns'] for r in events if r['action'] == 'saved' and all(
            r.get(key) in {'COMPLETE', 'SKIPPED_BY_CONFIG'}
            for key in ('scanner_review', 'business_review'))]
        duration = (min(complete)-min(reads))/1e6 if reads and complete else None
        review_windows.append(dict(batch=batch, review_completed=bool(complete),
            first_evidence_to_complete_ms=duration if duration is not None and duration >= 0 else None))
    # Union avoids counting overlapping MCP calls twice. Gaps include host work.
    merged = []
    for start, end in sorted(mcp_intervals):
        if merged and start <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])
    mcp_timing = dict(
        observed_window_ms=(merged[-1][1]-merged[0][0])/1e6 if merged else None,
        active_call_ms=sum(end-start for start, end in merged)/1e6 if merged else None,
        model_thinking_ms=None, first_call_to_final_reply_ms=None)
    scenario = manifest.get('scenario', 'smoke')
    missing = []
    if scenario.startswith('install-'):
        if not present & {'install.total', 'install.host_setup'}:
            missing.append('instrumented_install_runtime')
        if not manifest.get('shell_boundaries'):
            missing.append('installer_shell_boundaries')
    elif scenario.startswith('scan-') and 'scan.total' not in present:
        missing.append('instrumented_scan_runtime')
    elif scenario == 'mcp' and not any(p.startswith('mcp.') for p in present):
        missing.append('instrumented_mcp_server')
    return dict(run=manifest, phases=rows, queue=queue, review_windows=review_windows,
        mcp_timing=mcp_timing, missing_coverage=missing, unmatched_starts=len(starts.keys()-ends.keys()),
        unmatched_ends=len(ends.keys()-starts.keys()), rejected_events=rejected,
        possibly_capped_logs=capped, measurement_valid=bool(rows) and not missing and not rejected and not capped
            and starts.keys() == ends.keys(),
        interpretation='Inclusive spans; never sum phases. returned is not business success. '
            'Shell boundaries are observer arrival times. Missing coverage is unknown, not zero. '
            'Review windows include host/model waiting, not pure AI reasoning. '
            'Final reply time requires host conversation timestamps. '
            'Background workers may still be running; regenerate after saved terminal status.')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('directory', type=Path)
    args = parser.parse_args()
    result = report(args.directory)
    (args.directory/'report.json').write_text(json.dumps(result, indent=2)+'\n')
    print('Phase | count | median ms | max ms | p95 ms | raised')
    for row in result['phases']:
        print(' | '.join(str(row[k]) for k in ('phase','count','median_ms','max_ms','p95_ms','raised')))
    print(json.dumps({k:result[k] for k in ('mcp_timing', 'review_windows')}))
    print(json.dumps({k:result[k] for k in ('unmatched_starts','unmatched_ends','measurement_valid')}))


if __name__ == '__main__':
    main()
