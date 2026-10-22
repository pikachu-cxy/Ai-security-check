"""Real-engine JS/TS local-taint regression gate; targets are never executed.

Each generated file isolates one source-to-sink decision. This verifies route
and typed-handler boundaries, assignments, concatenation, overwrites, bound SQL
values and shell arguments. It does not model arbitrary wrapper functions.
"""
import argparse
import json
import tempfile
from pathlib import Path

from security_runtime.findings import FindingNormalizer
from security_runtime.models import ScanContext, ScanMode
from security_runtime.scanners import SemgrepAdapter
from security_runtime.verification_policy import local_recheck


PRELUDE = """import {type Request, type Response} from 'express';
import vm from 'node:vm';
import * as cp from 'node:child_process';
import * as fs from 'node:fs';
import { Pool } from 'pg';
const db = new Pool();
"""
# (function body, expected rule suffix). Other rule hits also fail the gate.
CASES = {
    'eval_assignment': ("const value = req.body.code; eval(value);", 'code-injection'),
    'function_concat': ("const value = req.body.code; new Function('return (' + value + ')');", 'code-injection'),
    'eval_reset': ("let value = req.body.code; value = '2+2'; eval(value);", None),
    'vm_code': ("vm.runInNewContext(req.body.code, {}, {timeout: 10});", 'code-injection'),
    'vm_data_only': ("vm.runInNewContext('input', {input: req.body.code});", None),
    'data_parser': ("JSON.parse(req.body.code);", None),
    'sql_concat': ("const value = req.query.id; db.query('SELECT * FROM users WHERE id=' + value);", 'sql-injection'),
    'sql_bound': ("db.query('SELECT * FROM users WHERE id=$1', [req.query.id]);", None),
    'sql_reset': ("let value = req.query.id; value = '1'; db.query('SELECT * FROM users WHERE id=' + value);", None),
    'shell_concat': ("const value = req.query.value; cp.exec('echo ' + value);", 'command-injection'),
    'shell_argv': ("cp.spawn('/bin/sh', ['-c', req.query.value]);", 'command-injection'),
    'plain_argv': ("cp.execFile('/usr/bin/printf', ['%s', req.query.value]);", None),
    'shell_reset': ("let value = req.query.value; value = 'fixed'; cp.exec('echo ' + value);", None),
    'file_read': ("const name = req.query.name; fs.readFileSync('/uploads/' + name);", 'arbitrary-file-read'),
    'file_read_reset': ("let name = req.query.name; name = 'fixed'; fs.readFileSync('/uploads/' + name);", None),
    'file_write': ("fs.writeFileSync(req.body.name, 'fixed contents');", 'arbitrary-file-write'),
    'file_write_data': ("fs.writeFileSync('/fixed/file', req.body.content);", None),
    'file_delete': ("fs.unlinkSync(req.body.name);", 'path-traversal'),
    'file_delete_fixed': ("fs.unlinkSync('/fixed/file');", None),
    'fetch_assignment': ("const url = req.query.url; fetch(url);", 'ssrf'),
    'fetch_reset': ("let url = req.query.url; url = 'https://fixed.example/'; fetch(url);", None),
    'fetch_fixed_host': ("fetch('https://fixed.example/search?q=' + encodeURIComponent(req.query.q));", None),
}


def cases():
    result = {}
    for name, (body, suffix) in CASES.items():
        # Standalone typed file-read/write sources are deliberately deferred:
        # the independent project exposed allowlist/lookup false positives.
        if not name.startswith(('file_read', 'file_write')):
            result[name + '.ts'] = (PRELUDE + 'export function handler(req: Request, res: Response) {\n'
                                   + body + '\n}\n', suffix)
        result[name + '.js'] = (PRELUDE.replace("import {type Request, type Response} from 'express';", '')
                               + "const app = require('express')();\napp.get('/', (req, res) => {\n"
                               + body + '\n});\n', suffix)
    result['unrelated.ts'] = ("function local(req: {body: {code: string}}) { return eval(req.body.code); }\n", None)
    result['unrelated.js'] = ("function local(req) { return eval(req.body.code); }\n", None)
    return result


def check():
    targets = cases()
    with tempfile.TemporaryDirectory(prefix='javascript-taint-quality-') as tmp:
        root = Path(tmp)
        for name, (source, _) in targets.items():
            (root / name).write_text(source, encoding='utf-8')
        with local_recheck():
            findings, run = SemgrepAdapter().scan(
                ScanContext(str(root), ScanMode.RELEASE, tuple(targets)), FindingNormalizer(root))
        if run.status != 'SUCCESS':
            raise ValueError(f'Product scan incomplete: {run.status}, {run.error}')
        actual = {(f.file_path, f.technical_details['rule_id']) for f in findings}
        expected = {(name, 'ai-security.javascript.' + suffix)
                    for name, (_, suffix) in targets.items() if suffix is not None}
        if actual != expected:
            raise ValueError(f'JS/TS product gate: missing={sorted(expected-actual)}, unexpected={sorted(actual-expected)}')
        return {'status': 'PASS', 'cases': len(targets), 'positive': len(expected),
                'negative': len(targets)-len(expected), 'findings': sorted(actual),
                'scope': 'Function-local taint only; no cross-file or arbitrary wrapper inference.'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    result = check()
    text = json.dumps(result, indent=2) + '\n'
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text, encoding='utf-8')
    print(text)
