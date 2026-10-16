"""Compare identical labelled cohorts, refusing changed labels or source bytes."""
import argparse
from collections import Counter
import json
from pathlib import Path


def load(paths, cohort):
    rows, hashes = {}, {}
    for path in paths:
        inventory = json.loads((path / 'inventory.json').read_text(encoding='utf-8'))
        if not json.loads((path / 'summary.json').read_text(encoding='utf-8'))['complete']:
            raise ValueError('Incomplete evaluation cannot pass the comparison gate')
        for row in json.loads((path / 'cases.json').read_text(encoding='utf-8')):
            if cohort != 'all' and row['split'] != cohort: continue
            key = row['case_id']
            if key in rows: raise ValueError('Duplicate case in comparison')
            rows[key] = row
            hashes[key] = inventory['source_hashes'][row['relative_file']]
    return rows, hashes


def metrics(rows):
    counts = Counter(r['outcome'] for r in rows)
    if counts.keys() - {'TP', 'FP', 'FN', 'TN', 'UNCERTAIN'}:
        raise ValueError('Unknown scoring outcome')
    result = {key: counts[key] for key in ('TP', 'FP', 'FN', 'TN', 'UNCERTAIN')}
    result['recall'] = counts['TP'] / (counts['TP'] + counts['FN']) if counts['TP'] + counts['FN'] else None
    result['precision'] = counts['TP'] / (counts['TP'] + counts['FP']) if counts['TP'] + counts['FP'] else None
    return result


def compare(before, after, cohort='all'):
    old, old_hashes = load(before, cohort)
    new, new_hashes = load(after, cohort)
    if not old or old.keys() != new.keys() or old_hashes != new_hashes:
        raise ValueError('Cohort or source bytes differ')
    for key in old:
        if any(old[key][field] != new[key][field] for field in ('relative_file', 'risk', 'group', 'cwe', 'split')):
            raise ValueError('Ground truth or split changed')
    groups = {}
    for group in sorted({r['group'] for r in old.values()}):
        ids = [key for key in old if old[key]['group'] == group]
        groups[group] = {'before': metrics([old[k] for k in ids]), 'after': metrics([new[k] for k in ids]),
            'changed_cases': [{'case_id': k, 'before': old[k]['outcome'], 'after': new[k]['outcome']}
                              for k in sorted(ids) if old[k]['outcome'] != new[k]['outcome']]}
    return {'cohort': cohort, 'cases': len(old), 'same_labels_and_source': True,
            'unit': 'FILE_AND_VULNERABILITY_CATEGORY; NOT_PRODUCTION_ACCURACY', 'groups': groups}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--before', nargs='+', type=Path, required=True)
    parser.add_argument('--after', nargs='+', type=Path, required=True)
    parser.add_argument('--cohort', choices=('all', 'train', 'holdout'), default='all')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = compare(args.before, args.after, args.cohort)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open('x', encoding='utf-8') as handle:
        json.dump(result, handle, ensure_ascii=False, indent=2)
        handle.write('\n')
    print(json.dumps({group: {k: v for k, v in values.items() if k != 'changed_cases'}
                      for group, values in result['groups'].items()}))
