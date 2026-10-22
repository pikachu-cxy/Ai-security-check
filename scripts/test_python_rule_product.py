"""Exercise SQL dictionary/configuration propagation through the real local engine.

Generated targets are scanned as text, never imported or executed. This gate is
separate from the raw YAML fixture gate because safe-key filtering belongs to
the product adapter, not Semgrep's whole-container taint model.
"""
import argparse
import json
import tempfile
from pathlib import Path

from security_runtime.findings import FindingNormalizer
from security_runtime.models import ScanContext, ScanMode
from security_runtime.scanners import SemgrepAdapter
from security_runtime.verification_policy import local_recheck


CASES = {
    'risk': ('d={}\nd["a"]="fixed"\nd["b"]=user\nd["c"]="another"\nx=d["b"]',
             'cur.execute("SELECT "+x)', True),
    'safe_key': ('d={}\nd["a"]="fixed"\nd["b"]=user\nd["c"]="another"\nx=d["a"]',
                 'cur.execute("SELECT "+x)', False),
    'overwrite_safe': ('d={}\nd["b"]=user\nd["b"]="fixed"\nx=d["b"]',
                       'cur.execute("SELECT "+x)', False),
    'overwrite_unsafe': ('d={}\nd["b"]="fixed"\nd["b"]=user\nx=d["b"]',
                         'cur.execute("SELECT "+x)', True),
    'bound': ('d={}\nd["b"]=user\nd["c"]="another"\nx=d["b"]',
              'cur.execute("SELECT ?",(x,))', False),
    'alias': ('d={}\nd["b"]=user\na=d\nx=a["b"]', 'cur.execute("SELECT "+x)', True),
    'safe_get': ('d={}\nd["a"]="fixed"\nd["b"]=user\nx=d.get("a")',
                 'cur.execute("SELECT "+x)', False),
    'risk_get': ('d={}\nd["a"]="fixed"\nd["b"]=user\nx=d.get("b")',
                 'cur.execute("SELECT "+x)', True),
    'missing_default': ('d={}\nd["b"]=user\nx=d.get("absent","fixed")',
                        'cur.execute("SELECT "+x)', False),
}

# Configuration propagation is deliberately limited to adjacent set/get of the
# same section and option. Safe keys must stay safe in the raw engine too.
CONFIG_START = 'import configparser\nc=configparser.ConfigParser()\nc.add_section("s")\n'
CONFIG_CASES = {
    'config_risk': ('c.set("s","a",user)\nx=c.get("s","a")', True),
    'config_safe_key': ('c.set("s","a","fixed")\nc.set("s","b",user)\nx=c.get("s","a")', False),
    'config_safe_section': ('c.add_section("t")\nc.set("s","a","fixed")\nc.set("t","a",user)\nx=c.get("s","a")', False),
    'config_overwrite_safe': ('c.set("s","a",user)\nc.set("s","a","fixed")\nx=c.get("s","a")', False),
    'config_overwrite_risk': ('c.set("s","a","fixed")\nc.set("s","a",user)\nx=c.get("s","a")', True),
    'config_copied_value': ('c.set("s","a",user)\nx=c.get("s","a")\nc.set("s","a","fixed")', True),
    'config_scalar_reset': ('c.set("s","a",user)\nx=c.get("s","a")\nx="fixed"', False),
    'config_bound': ('c.set("s","a",user)\nx=c.get("s","a")', False),
}
for name, (body, risk) in CONFIG_CASES.items():
    sink = 'cur.execute("SELECT ?",(x,))' if name == 'config_bound' else 'cur.execute("SELECT "+x)'
    CASES[name] = (CONFIG_START+body, sink, risk)


def check():
    with tempfile.TemporaryDirectory(prefix='python-sql-quality-') as tmp:
        root = Path(tmp)
        for name, (body, sink, _) in CASES.items():
            text = 'import flask\ndef f(cur):\n    user=flask.request.headers.get("X-User")\n'
            text += ''.join('    '+line+'\n' for line in (body+'\n'+sink).splitlines())
            (root/(name+'.py')).write_text(text, encoding='utf-8')
        with local_recheck():
            found, run = SemgrepAdapter().scan(
                ScanContext(str(root), ScanMode.RELEASE, tuple(name+'.py' for name in CASES)),
                FindingNormalizer(root))
        if run.status != 'SUCCESS':
            raise ValueError(f'Product scan incomplete: {run.status}, {run.error}')
        actual = {f.file_path for f in found if f.technical_details['rule_id'] == 'ai-security.python.sql-injection'}
        expected = {name+'.py' for name, (_, _, risk) in CASES.items() if risk}
        if actual != expected:
            raise ValueError(f'SQL product gate: missing={expected-actual}, unexpected={actual-expected}')
        return {'status': 'PASS', 'cases': len(CASES), 'findings': sorted(actual),
                'constant_proof': run.scanner_diagnostics.get('constant_proof')}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    result = check()
    text = json.dumps(result, indent=2)+'\n'
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text, encoding='utf-8')
    print(text)
