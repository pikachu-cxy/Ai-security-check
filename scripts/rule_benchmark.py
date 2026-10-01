"""Actual Jeepay scan and two independently authored local Java benchmarks."""
import argparse
from pathlib import Path
import json
import os
import sqlite3
import tempfile
import shutil
from contextlib import closing
from progress_acceptance import capture
from security_runtime.rulepacks import RulePackManager


def run(project,output):
    evidence={'notes':['Actual Jeepay; no dependency build commands or registry rules.',
        'Benchmark labels are manual code review annotations, not AI triage.']}
    with tempfile.TemporaryDirectory(prefix='rule-benchmark-') as temporary:
        base=Path(temporary)
        state=base/'state'
        env=dict(os.environ,SECURITY_RUNTIME_STATE_DIR=str(state))
        actual=capture(['scan','--mode','release'],project,env)
        assert actual['exit_code'] in (0,1),actual
        with closing(sqlite3.connect(state/'scans.db')) as db:
            payload=json.loads(db.execute('SELECT data FROM scans ORDER BY rowid DESC LIMIT 1').fetchone()[0])
        semgrep=next(run for run in payload['scanner_runs'] if run['scanner']=='semgrep')
        java=payload['rule_coverage']['per_language']['java']
        assert java['executed_rules']>0 and java['status'] in ('EXECUTED','PARTIAL')
        assert payload['rule_coverage']['per_language']['javascript']['status']=='NOT_COVERED'
        assert not any(Path(name).suffix.lower() in {'.js','.vue','.yml','.yaml','.md'} for name in payload['rule_coverage']['scope_files'])
        evidence['jeepay']={'cli':actual,'result':payload,'semgrep_duration_ms':semgrep['duration_ms'],
            'semgrep_findings':[f for f in payload['findings'] if 'semgrep' in f['scanner_sources']],
            'java_files':sum(Path(name).suffix.lower()=='.java' for name in payload['target_profile']['files'])}
        pack=RulePackManager().resolve()
        evidence['independent_benchmarks']={}
        for name,candidates in [('spring-rest',('runtime-exec','spring-jdbc','spring-resttemplate','open-redirect')),
                                ('jdbc',('jdbc-statement','file-access','url-connection','object-deserialization'))]:
            template=Path(__file__).resolve().parents[1]/'samples/java-benchmarks'/name
            source=base/name
            shutil.copytree(template,source)
            record=capture(['scan','--mode','release','--json'],source,env)
            assert record['exit_code'] in (0,1)
            result=json.loads(record['stdout'])
            actual_ids={f['technical_details']['rule_id'] for f in result['findings'] if 'semgrep' in f['scanner_sources']}
            assert actual_ids=={'ai-security.java.'+value for value in candidates},actual_ids
            for finding in result['findings']:
                lines=(source/finding['file_path']).read_text(encoding='utf-8').splitlines()
                assert lines[finding['line_start']-2].strip()=='// expected: '+finding['technical_details']['rule_id']
            evidence['independent_benchmarks'][name]={'cli':record,'result':result}
    output.write_text(json.dumps(evidence,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print('Actual rule benchmark evidence recorded: '+str(output),flush=True)


if __name__=='__main__':
    import sys
    sys.stdout.reconfigure(encoding='utf-8')
    parser=argparse.ArgumentParser();parser.add_argument('--project',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();run(args.project,args.output)
