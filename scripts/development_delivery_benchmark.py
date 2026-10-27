"""Measure local metadata-stage costs, NOT scanner or complete-chat latency."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import statistics
import tempfile
import time

from security_runtime.development_check import DevelopmentCheckService
from security_runtime.development_continuation import stop
from security_runtime.development_delivery import publish
from security_runtime.hook_state import HookStateStore


def measure(operation, rounds):
    operation()  # Exclude one warm-up, keep filesystem caches as observed.
    samples = []
    for _ in range(rounds):
        start = time.perf_counter_ns()
        operation()
        samples.append((time.perf_counter_ns()-start)/1_000_000)
    return dict(rounds=rounds, median_ms=statistics.median(samples), max_ms=max(samples), samples_ms=samples)


def run(directory, rounds):
    root = directory/'project'
    root.mkdir()
    hooks = HookStateStore(directory/'private')
    owner = dict(host='codex', session='1'*64)
    service = DevelopmentCheckService(None, hooks, owner=owner,
        scan_path_provider=directory/'scans.db', launcher=lambda *args: None)
    measurements = dict(empty_stop=measure(lambda: stop(hooks, root, owner), rounds))
    ref = service.begin(root, 'metadata-cost')['check_ref']
    service.record(root, ref, [], scope_unknown=True)
    service.finish(root, ref)
    store = service.store(root)
    with store.transaction() as db:
        row = store._put(db, ref, dict(store._get(db, ref), state='PARTIAL', scanned_seq=1,
            reason_code='DEVELOPMENT_SCOPE_UNKNOWN'))
        publish(store, db, row)
    measurements['saved_status_read'] = measure(lambda: service.get(root, ref), rounds)
    measurements['completed_offered_stop'] = measure(lambda: stop(hooks, root, owner, offered={(ref, 1)}), rounds)
    measurements['pending_delivery_page'] = measure(lambda: service.deliveries(root), rounds)
    return dict(contract='development-delivery-metadata-cost-v1', measurements=measurements,
        limitations=['Metadata-only synthetic unknown-scope terminal record; no scanner or model executed.',
            'Independent stage costs, not an end-to-end before/after speed comparison.',
            'One warm-up per stage; caches retained; platform/filesystem-specific.'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--temp-root', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--rounds', type=int, default=30)
    args = parser.parse_args()
    if not 20 <= args.rounds <= 1000:
        parser.error('rounds must be between 20 and 1000')
    args.temp_root.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='delivery-cost-', dir=args.temp_root) as directory:
        result = run(Path(directory), args.rounds)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2)+'\n', encoding='utf-8')
    print(json.dumps({name: {k:v for k,v in value.items() if k != 'samples_ms'}
                      for name,value in result['measurements'].items()}, indent=2))


if __name__ == '__main__':
    main()
