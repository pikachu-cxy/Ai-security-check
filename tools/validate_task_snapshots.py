"""Verify signed task states separately from a budgeted setup observation."""
import argparse
import json
from pathlib import Path
from security_runtime.tasks.security import TaskSecurityService, digest_value
from security_runtime.hook_state import HookStateStore


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('before', type=Path); ap.add_argument('after', type=Path)
    ap.add_argument('--before-work', type=Path, required=True)
    ap.add_argument('--after-work', type=Path, required=True)
    ap.add_argument('--output', type=Path, required=True)
    args = ap.parse_args()
    rows = {}
    for data_path, work in ((args.before,args.before_work),(args.after,args.after_work)):
        data = json.loads(data_path.read_text(encoding='utf-8'))
        work = work.resolve()
        side = {}
        for row in data['rows']:
            sample, iteration = row['project']['sample'], row['iteration']
            root = work/sample
            svc = TaskSecurityService(None, HookStateStore(work/f'state-{sample}-{iteration}'))
            record = svc.load(root, row['result']['task_ref'])
            item = dict(baseline_hashes=digest_value(record['baseline']['hashes']),
                end_hashes=digest_value(record['end']['hashes']),
                baseline_inventory=digest_value(record['baseline'].get('inventory')),
                end_inventory=digest_value(record['end'].get('inventory')),
                baseline_files=len(record['baseline']['hashes']),
                end_files=len(record['end']['hashes']),
                bytes=sum((root/p).stat().st_size for p in record['baseline']['hashes']),
                baseline_limits=record['baseline']['limitations'],
                end_limits=record['end']['limitations'], limitations=record['limitations'],
                baseline_complete=record['baseline'].get('inventory_complete'),
                end_complete=record['end'].get('inventory_complete'),
                host_coverage=record['review']['coverage'])
            side[f'{sample}:{iteration}'] = item
        rows[data_path.name] = side
    b,a = rows.values()
    if b != a:
        raise ValueError('Signed actual task snapshots or coverage differ')
    args.output.write_text(json.dumps(dict(status='PASS', sides=rows), indent=2, ensure_ascii=False), encoding='utf-8')
    print('Signed begin/end snapshot identities and limitations: PASS')


if __name__ == '__main__': main()
