"""Offline capability corpus accounting using actual managed scanner adapters.

The labels are author-declared synthetic expectations, never independent human
production ground truth. Reports contain coordinates/identities/counts only.
"""
from __future__ import annotations
from pathlib import Path, PurePosixPath
from dataclasses import asdict
import json
import shutil
import tempfile

from .findings import FindingNormalizer
from .models import ScanContext, ScanMode, RunStatus
from .scanners import SemgrepAdapter, GitleaksAdapter
from .verification_policy import local_recheck


def load_corpus(path, program):
    path = Path(path).resolve()
    document = json.loads(path.read_text(encoding='utf-8'))
    if document.get('schema_version') != 'rule-ground-truth-v1' or document.get('kind') not in {'SYNTHETIC','OSS','INTERNAL'}:
        raise ValueError('Ground Truth corpus schema invalid')
    capabilities = {c.capability_id for c in program.capabilities}
    cases = document.get('cases')
    if not isinstance(cases,list) or not 1 <= len(cases) <= 500:
        raise ValueError('Ground Truth corpus budget invalid')
    seen = set()
    for case in cases:
        if not isinstance(case,dict) or case.get('case_id') in seen or case.get('expected_capability') not in capabilities:
            raise ValueError('Ground Truth fixture identity invalid')
        seen.add(case['case_id'])
        name = case.get('file',''); relative = PurePosixPath(name)
        if not name or relative.is_absolute() or '..' in relative.parts or ':' in name or '\\' in name:
            raise ValueError('Ground Truth fixture path invalid')
        file = path.parent / name
        if not file.is_file() or file.is_symlink() or file.is_junction() or not file.resolve().is_relative_to(path.parent) or file.stat().st_size > 100000:
            raise ValueError('Ground Truth fixture scope invalid')
        if type(case.get('expected_occurrences')) is not int or not 0 <= case['expected_occurrences'] <= 100 or type(case.get('risk')) is not bool or case['risk'] != bool(case['expected_occurrences']):
            raise ValueError('Ground Truth occurrence contract invalid')
    return document


def evaluate(corpus, findings):
    actual = {}
    for finding in findings:
        row = asdict(finding) if not isinstance(finding,dict) else finding
        details = row.get('technical_details',{})
        capability = details.get('capability_id')
        if not capability:
            continue
        key = (row['file_path'],capability)
        # Never collapse distinct source coordinates. Scanner detector repeats
        # at the same secret location retain their detector identity.
        point = (row['line_start'],row['line_end'],details['rule_id'])
        actual.setdefault(key,set()).add(point)
    totals = {'TP':0,'TN':0,'FP':0,'FN':0}; per = {}; results=[]
    for case in corpus['cases']:
        cid = case['expected_capability']; expected = case['expected_occurrences']
        observed = len(actual.pop((case['file'],cid),()))
        metrics = {'TP':min(expected,observed),'FN':max(0,expected-observed),
            'FP':max(0,observed-expected),'TN':int(expected == 0 and observed == 0)}
        for other in [key for key in actual if key[0] == case['file']]:
            metrics['FP'] += len(actual.pop(other))
        row = per.setdefault(cid,{'TP':0,'TN':0,'FP':0,'FN':0,'cases':0,'variants':[]})
        row['cases'] += 1
        if case['variant'] not in row['variants']: row['variants'].append(case['variant'])
        for metric,n in metrics.items(): totals[metric] += n; row[metric] += n
        results.append({'case_id':case['case_id'],'file':case['file'],'capability_id':cid,
            'expected_occurrences':expected,'observed_occurrences':observed,**metrics})
    unexpected = sum(len(points) for points in actual.values())
    totals['FP'] += unexpected
    return {'kind':corpus['kind'],'independent_human_ground_truth':corpus['independent_human_ground_truth'],
        'totals':totals,'per_capability':per,'cases':results,'unexpected_outside_fixture':unexpected,
        'quality_status':'PASS' if totals['FP'] == totals['FN'] == 0 else 'MISMATCH'}


def run_corpus(path, *, tool_manager=None):
    from .rulepacks import RulePackManager
    pack = RulePackManager().resolve(); corpus = load_corpus(path,pack.program)
    with tempfile.TemporaryDirectory(prefix='rule-program-corpus-') as temp:
        root = Path(temp)
        for case in corpus['cases']:
            destination = root / case['file']; destination.parent.mkdir(parents=True,exist_ok=True)
            shutil.copyfile(Path(path).parent / case['file'],destination)
        context = ScanContext(str(root),ScanMode.QUICK,tuple(case['file'] for case in corpus['cases']))
        normalizer = FindingNormalizer(root); findings = []; runs=[]
        for adapter in (SemgrepAdapter(tool_manager),GitleaksAdapter(tool_manager)):
            with local_recheck():
                found,run = adapter.scan(context,normalizer)
            if run.status != RunStatus.SUCCESS:
                raise ValueError('Real corpus engine did not succeed: '+adapter.name+' '+run.error_code)
            findings.extend(found)
            runs.append({'scanner':adapter.name,'version':run.version,'duration_ms':run.duration_ms,
                'status':run.status,'finding_count':len(found),'rule_coverage':run.rule_coverage,
                'scanner_diagnostics':run.scanner_diagnostics})
        report=evaluate(corpus,findings)
        report.update(program_version=pack.program.version,rule_pack_checksum=pack.checksum,scanner_runs=runs,
            applicable_capabilities=len(pack.program.capabilities),
            installed_semgrep_rules=len(pack.catalog),
            capability_owned_semgrep_rules=sum(len(c.underlying_rule_ids) for c in pack.program.capabilities if c.scanner_engine=='semgrep'),
            applicable_underlying_rules=runs[0]['rule_coverage']['total_selected'],
            provider_owned_secret_rules='GITLEAKS_BUILT_IN_DETECTORS; NO RUNTIME RULE OVERRIDE')
        # Validate evidence expectations independently of occurrence counts.
        for case in corpus['cases']:
            for expected in case['expected']:
                matches=[f for f in findings if f.file_path == case['file'] and
                    f.technical_details.get('capability_id') == expected['capability_id']]
                if matches and any(f.technical_details['detection_evidence']['basis'] != expected['evidence_basis'] for f in matches):
                    raise ValueError('Capability evidence basis mismatch')
            if case['expected_occurrences'] and case['related_capabilities']:
                matches=[f for f in findings if f.file_path == case['file']]
                if any(set(f.technical_details.get('related_capabilities',[])) != set(case['related_capabilities']) for f in matches):
                    raise ValueError('Capability overlap evidence mismatch')
        return report
