"""First-party rule quality gate: catalog, engine loading and exact positive/negative expectations."""
from __future__ import annotations
import argparse
from pathlib import Path
import json
import re

from security_runtime.rulepacks import RulePackManager
from security_runtime.processes import run_process
from security_runtime.toolchain import ToolManager, ToolStatus, tool_environment, external_tool_loader


def expectations(root, catalog):
    expected=set();negative=set();counts={}
    known={record.rule_id for record in catalog}
    for record in catalog:
        file=root/record.fixture
        if not file.is_file() or not file.resolve().is_relative_to(root.resolve()):
            raise ValueError('Rule fixture missing or outside repository')
        lines=file.read_text(encoding='utf-8').splitlines()
        yes=no=0
        for index,line in enumerate(lines):
            match=re.search(r'\b(ruleid|ok):\s*([a-zA-Z0-9_.-]+(?:\s*,\s*[a-zA-Z0-9_.-]+)*)',line)
            if match:
                next_line=index+2
                while next_line<=len(lines) and not lines[next_line-1].strip(): next_line+=1
                for rid in [value.strip() for value in match[2].split(',')]:
                    if rid in known:
                        (expected if match[1]=='ruleid' else negative).add((rid,record.fixture,next_line))
            if match and record.rule_id in [value.strip() for value in match[2].split(',')]:
                next_line=index+2
                while next_line<=len(lines) and not lines[next_line-1].strip(): next_line+=1
                item=(record.rule_id,record.fixture,next_line)
                if match[1]=='ruleid': yes+=1
                else: no+=1
        if not yes or not no:
            raise ValueError('Rule requires positive and negative fixtures: '+record.rule_id)
        counts[record.rule_id]={'positive':yes,'negative':no}
    return expected,negative,counts


def check(root=None, *, lint_only=False):
    root=root or Path(__file__).resolve().parents[1]
    pack=RulePackManager().resolve()
    expected,negative,counts=expectations(root,pack.catalog)
    report={'rule_pack':pack.descriptor.rule_pack_id,'version':pack.descriptor.version,'checksum':pack.checksum,
        'rules':len(pack.catalog),'positive':sum(c['positive'] for c in counts.values()),
        'negative':sum(c['negative'] for c in counts.values()),'cases':counts}
    if not lint_only:
        tool=ToolManager().resolve('semgrep')
        if tool.status!=ToolStatus.READY:
            raise ValueError('Rule gate requires the pinned Semgrep test engine')
        common=[tool.path,'scan','--config',str(pack.path),'--metrics','off','--disable-version-check']
        environment=tool_environment(Path(tool.path))
        # Semgrep's Python CLI reads local YAML with its locale encoding.
        environment['PYTHONUTF8']='1'
        with external_tool_loader():
            validated=run_process([*common,'--validate'],cwd=root,env=environment,timeout=90)
            if validated.returncode!=0:
                raise ValueError('Semgrep could not load the local pack: '+validated.stderr[-2000:])
            files=sorted({record.fixture for record in pack.catalog})
            result=run_process([*common,'--json','--quiet','--no-rewrite-rule-ids','--no-git-ignore',*files],
                cwd=root,env=environment,timeout=90)
        data=json.loads(result.stdout)
        if result.returncode not in (0,1) or data.get('errors'):
            raise ValueError('Semgrep fixture execution failed: '+str(data.get('errors',[])))
        actual={(r['check_id'],r['path'].replace('\\','/'),r['start']['line']) for r in data['results']}
        # Exact equality also rejects unexpected findings elsewhere in safe fixture code.
        if actual!=expected or actual&negative:
            raise ValueError('Rule fixtures mismatch: missing='+repr(sorted(expected-actual))+' unexpected='+repr(sorted(actual-expected)))
        report.update(engine=tool.version,lint='PASS',fixtures='PASS')
    else:
        report['lint']='PASS'
    return report


if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--lint-only',action='store_true')
    parser.add_argument('--output',type=Path)
    args=parser.parse_args()
    result=check(lint_only=args.lint_only)
    if args.output:
        args.output.parent.mkdir(parents=True,exist_ok=True)
        args.output.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(result,indent=2))
