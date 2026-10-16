"""Offline CE comparison of an immutable corpus with a pinned public rules checkout.

Third-party rules stay outside the distributable product. No target code executes.
The selection is all Java/Python rules declaring CWE-22/23/36/73/89, not a hand-picked
subset. This is the public CE repository, not Registry auto or commercial Code.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import re
import subprocess
import time

import yaml

from rule_quality_evaluation import metrics, source, write


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def select_rules(checkout, language, registry_file=None):
    definitions, inventory, categories = [], [], {}
    paths = [registry_file] if registry_file else sorted((checkout / language).rglob('*'))
    for path in paths:
        if not registry_file and path.suffix not in {'.yaml', '.yml'}: continue
        for original in (yaml.safe_load(path.read_text(encoding='utf-8')) or {}).get('rules', []):
            if language not in original.get('languages', []): continue
            metadata = original.get('metadata', {})
            cwes = metadata.get('cwe', [])
            if isinstance(cwes, str): cwes = [cwes]
            groups = {('sqli' if match.group(1) == '89' else 'pathtraver')
                      for text in cwes if (match := re.match(r'CWE-(22|23|36|73|89)\b', str(text)))}
            if not groups: continue
            relative = path.name if registry_file else path.relative_to(checkout).as_posix()
            identifier = original['id'] if registry_file else relative.removesuffix(path.suffix).replace('/', '.') + '.' + original['id']
            if identifier in categories: raise ValueError('Duplicate qualified rule id')
            categories[identifier] = groups
            definitions.append(dict(original, id=identifier))
            inventory.append({'id':identifier, 'upstream_id':original['id'], 'file':relative,
                              'sha256':sha(path), 'groups':sorted(groups), 'metadata':metadata,
                              'languages':original['languages']})
    if not definitions: raise ValueError('No applicable public rules')
    return definitions, inventory, categories


def execution_observed(data, definitions, batch):
    extensions={Path(name).suffix for name in batch}
    required={r['id'] for r in definitions if any(
        ext in extensions for lang,ext in [('java','.java'),('python','.py')] if lang in r['languages'])}
    executed=data.get('time',{}).get('rules',[])
    return bool(required) and required <= {r for r in executed if isinstance(r,str)}


def run(args):
    registry_file = args.registry_file.resolve() if args.registry_file else None
    checkout = args.rules.resolve() if args.rules else registry_file.parent
    baseline, output = args.baseline.resolve(), args.output.resolve()
    inv = json.loads((baseline/'inventory.json').read_text(encoding='utf-8'))
    root = Path(inv['root'])
    language = inv['kind']
    if language not in {'java', 'python', 'unlabelled'}: raise ValueError('Unsupported cohort')
    if output.is_relative_to(root) or root.is_relative_to(output): raise ValueError('Overlapping corpus/output')
    output.mkdir(parents=True, exist_ok=False)
    names = sorted(inv['source_hashes'])
    if {name:sha(source(root,name)) for name in names} != inv['source_hashes']:
        raise ValueError('Corpus differs from recorded baseline')
    revision = sha(registry_file) if registry_file else subprocess.check_output(['git','-C',str(checkout),'rev-parse','HEAD'],timeout=30).decode().strip()
    if not registry_file and subprocess.check_output(['git','-C',str(checkout),'status','--porcelain'],timeout=30).strip():
        raise ValueError('Public checkout is modified')
    definitions, inventory, categories = [], [], {}
    for lang in (['java','python'] if language=='unlabelled' else [language]):
        rules, items, groups = select_rules(checkout,lang,registry_file)
        definitions.extend(rules); inventory.extend(items); categories.update(groups)
    config = output/'selected-public-rules.yml'
    config.write_text('# Local evaluation copy; original rule bodies/notices retained. IDs qualified only.\n'+
                      '# Semgrep Rules License v1.0: https://semgrep.dev/legal/rules-license/\n'+
                      yaml.safe_dump({'rules':definitions},sort_keys=False),encoding='utf-8')
    write(output/'rules-inventory.json', {'repository':'https://semgrep.dev/c/p/default' if registry_file else 'https://github.com/semgrep/semgrep-rules',
        'commit':revision,'selection':'ALL_CWE_22_23_36_73_89_IN_JAVA_PYTHON','rules':inventory,
        'engine':'Semgrep CE','engine_version':importlib.metadata.version('semgrep'),
        'config_sha256':sha(config),'license':'SEE_EACH_RULE_METADATA' if registry_file else (checkout/'LICENSE').read_text(encoding='utf-8'),
        'upstream_missed':(yaml.safe_load(registry_file.read_text(encoding='utf-8')) or {}).get('missed') if registry_file else None})
    write(output/'inventory.json',inv)
    env = dict(os.environ, SEMGREP_SETTINGS_FILE=str(output/'settings.yml'),
        SEMGREP_LOG_FILE=str(output/'semgrep.log'), SEMGREP_ENABLE_VERSION_CHECK='0',
        SEMGREP_SEND_METRICS='off', SECURITY_RUNTIME_OFFLINE='1')
    (output/'settings.yml').write_text('{}\n',encoding='utf-8')
    observations, hits, failed, scanned = [], {}, set(), set()
    for start in range(0,len(names),80):
        batch = names[start:start+80]
        command=[str(args.executable.resolve()),'scan','--config',str(config),'--json','--time','--quiet',
                 '--metrics','off','--disable-version-check','--no-rewrite-rule-ids','--no-git-ignore',*batch]
        before=time.monotonic()
        result=subprocess.run(command,cwd=root,env=env,capture_output=True,timeout=180)
        elapsed=round((time.monotonic()-before)*1000)
        (output/f'batch-{start//80:03d}.stderr.txt').write_bytes(result.stderr)
        data=json.loads(result.stdout)
        write(output/f'batch-{start//80:03d}.json',data)
        clean=(result.returncode in (0,1) and not data.get('errors') and
               execution_observed(data,definitions,batch))
        paths={Path(p).as_posix() for p in data.get('paths',{}).get('scanned',[])}
        scanned.update(paths)
        if not clean: failed.update(batch)
        failed.update(set(batch)-paths)
        for finding in data.get('results',[]):
            name=Path(finding['path']).as_posix()
            for group in categories.get(finding['check_id'],[]): hits.setdefault((name,group),[]).append(finding['check_id'])
        observation={'batch':start//80,'files':len(batch),'scanned':len(set(batch)&paths),
                     'errors':len(data.get('errors',[])),'returncode':result.returncode,
                     'duration_ms':elapsed,'findings':len(data.get('results',[]))}
        observations.append(observation)
        print(json.dumps(observation),flush=True)
    if {name:sha(source(root,name)) for name in names} != inv['source_hashes']:
        raise ValueError('Source changed during evaluation')
    if any(sha(checkout/item['file'])!=item['sha256'] for item in inventory): raise ValueError('Rules changed')
    rows = json.loads((baseline/'cases.json').read_text(encoding='utf-8')) if language!='unlabelled' else []
    for row in rows:
        detected=bool(hits.get((row['relative_file'],row['group'])))
        row['outcome']='UNCERTAIN' if row['relative_file'] in failed else (
            ('TP' if row['risk'] else 'FP') if detected else ('FN' if row['risk'] else 'TN'))
        row['matched_rules']=hits.get((row['relative_file'],row['group']),[])
    write(output/'cases.json',rows)
    summary={'complete':not failed,'kind':language,'files':len(names),'rules':len(inventory),
             'rule_groups':dict(Counter(group for item in inventory for group in item['groups'])),
             'public_commit':revision,'batches':observations,'failed_files':sorted(failed),
             'groups':{g:metrics([r for r in rows if r['group']==g]) for g in sorted({r['group'] for r in rows})},
             'findings':sum(o['findings'] for o in observations),'total_duration_ms':sum(o['duration_ms'] for o in observations),
             'target_execution':False,'source_upload':False,'engine':'CE; NOT_COMMERCIAL_CODE',
             'metrics_unit':'FILE_AND_CWE_GROUP; NOT_FINDING_COUNT_OR_PRODUCTION_ACCURACY'}
    write(output/'summary.json',summary)
    print(json.dumps(summary),flush=True)
    return 0 if summary['complete'] else 2


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    selection=parser.add_mutually_exclusive_group(required=True)
    selection.add_argument('--rules',type=Path)
    selection.add_argument('--registry-file',type=Path)
    parser.add_argument('--baseline',type=Path,required=True)
    parser.add_argument('--executable',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    raise SystemExit(run(parser.parse_args()))
