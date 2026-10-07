"""Actual offline managed engines; no source/credential text in the report."""
import argparse
import json
from pathlib import Path
from security_runtime.rule_ground_truth import run_corpus

if __name__ == '__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    root=Path(__file__).resolve().parents[1]
    report=run_corpus(root/'tests/rule_program/corpus.json')
    args.output.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({'quality_status':report['quality_status'],'totals':report['totals'],
        'per_capability':report['per_capability']},indent=2))
    raise SystemExit(0 if report['quality_status'] == 'PASS' else 1)
