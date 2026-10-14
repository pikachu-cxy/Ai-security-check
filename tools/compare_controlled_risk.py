"""Compare real originating-engine risk/repair/recheck evidence."""
import argparse
import json
import hashlib
from datetime import datetime, timezone
import uuid
from pathlib import Path


def require(value,message):
    if not value: raise ValueError(message)


def canonical_scan(scan):
    return dict(status=scan['status'],coverage=scan['coverage'],scope=scan['scope_files'],actual=scan['actual_files'],
        capabilities=scan['capability_results'],
        providers=sorted((r['scanner'],r['version'],r['status'],r['coverage_contract']) for r in scan['scanner_runs']),
        rule_programs={r['scanner']:{k:r['rule_coverage'].get(k) for k in
            ('rule_pack_id','rule_pack_version','rule_pack_checksum','capability_program_version','scope_files','per_language','status')}
            for r in scan['scanner_runs'] if r['rule_coverage']},
        findings=sorted((f['file_path'],f['line_start'],f['line_end'],f['category'],f['severity'],
            f['technical_details']['rule_id'],f['technical_details'].get('rule_version'),
            f['technical_details'].get('rule_pack_checksum'),tuple(f['scanner_sources'])) for f in scan['findings']))


def compare(before,after):
    for row in (before,after):
        require(row['status']=='SUCCESS' and row['run_id'] and row['finished_at_utc'],'This invocation did not succeed')
        origin=row['runtime_identity']
        require(origin['version']==origin['expected_version'] and origin['task_source_sha256']==origin['expected_task_source_sha256'],
                'Loaded Runtime differs from expected source/version')
        require(origin['source_sha256'] and origin['package_python_sha256'],'Missing loaded-source identity')
        require(row['artificial_injection'] is True and row['application_executed'] is False,'Scenario scope incorrect')
        require(row['explicit_choice']['approved'] is True and row['explicit_choice']['choice']=='修复','Missing explicit choice')
        require(row['fix_preparation']['authorization_requirements']['user_consent_required'] is True,'Preparation inferred consent')
        require(row['verification']['status']=='SCANNER_VERIFIED_RESOLVED','Risk resolution not verified')
        require(row['verification']['runtime_observed_execution']['scanner_recheck'] is True and
                row['verification']['runtime_observed_execution']['engine_process_observed'] is True,'No real engine recheck')
        require(row['full_security_acceptance'] is False,'Cannot claim full safety')
        for name in ('unsafe_static','safe_static'):
            scan=row[name]
            require(scan['status']=='COMPLETED' and scan['coverage'] in {'FULL','SCOPED'},'Scan incomplete')
            require(all(r['status'] in {'SUCCESS','NOT_APPLICABLE'} and r['coverage_contract']=='FULL' for r in scan['scanner_runs']),'Provider incomplete')
        risks=[f for f in row['unsafe_static']['findings'] if f['technical_details']['rule_id']=='ai-security.python.unsafe-yaml']
        require(len(risks)==1 and 'semgrep' in risks[0]['scanner_sources'],'No real injected-risk finding')
        require(not row['safe_static']['findings'],'Unexpected findings after controlled repair')
    for key in ('project','commit','archive_sha256','baseline_hashes','unsafe_hashes','safe_hashes','final_file_sha256'):
        require(before[key]==after[key],'Content identity differs: '+key)
    require(before['run_id'] != after['run_id'],'Same invocation cannot stand in for both versions')
    require(before['runtime_identity']['task_source_sha256'] != after['runtime_identity']['task_source_sha256'],
            'Baseline and optimized task implementations must have distinct recorded identities')
    require(canonical_scan(before['unsafe_static'])==canonical_scan(after['unsafe_static']),'Unsafe findings/coverage differ')
    require(canonical_scan(before['safe_static'])==canonical_scan(after['safe_static']),'Fixed findings/coverage differ')
    return dict(status='PASS',scope='Artificial injection in same authorized real-project component',
        project=before['project'],commit=before['commit'],artificial_injection=True,
        unsafe=canonical_scan(before['unsafe_static']),fixed=canonical_scan(before['safe_static']),
        verification_status='SCANNER_VERIFIED_RESOLVED',engine_process_observed=True,
        explicit_choice='HOST_REPORTED_CONTROLLED_SCENARIO_CHOICE',application_executed=False,
        before_run_id=before['run_id'],after_run_id=after['run_id'],
        runtime_sources=dict(before=before['runtime_identity'],after=after['runtime_identity']),
        full_security_acceptance=False)


def main():
    ap=argparse.ArgumentParser(); ap.add_argument('before',type=Path); ap.add_argument('after',type=Path)
    ap.add_argument('--output',type=Path,required=True); args=ap.parse_args()
    require(not args.output.exists(),'Use a new comparison output; do not reuse a previous success')
    data=[json.loads(p.read_text(encoding='utf-8')) for p in (args.before,args.after)]
    result=compare(*data)
    result.update(comparison_id=uuid.uuid4().hex,finished_at_utc=datetime.now(timezone.utc).isoformat(),
        input_records={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in (args.before,args.after)})
    args.output.write_text(json.dumps(result,indent=2,ensure_ascii=False),encoding='utf-8')
    print('Controlled real-engine before/after finding, repair and coverage comparison: PASS')


if __name__=='__main__': main()
