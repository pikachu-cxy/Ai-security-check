"""Import execution YAML from a pinned upstream checkout.

One equivalent publication escape is recorded explicitly. Only rule definitions are shipped, not upstream test targets or CI configs.
Non-rule files are enumerated in the import receipt; malformed rule-like inputs
fail rather than silently reducing the pack. Run explicitly during development.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import re

import yaml

COMMIT = 'f1d2b562b414783763fd02a6ed2736eaed622efa'


PATCHED_RULE = 'generic/secrets/security/detected-slack-webhook.yaml'


def publication_bytes(name, content):
    """Escape a documented dummy URL without changing the parsed rule."""
    if name != PATCHED_RULE:
        return content
    lines = content.splitlines(keepends=True)
    for index, line in enumerate(lines):
        if b'pattern-not: https:' in line:
            prefix, value = line.split(b'pattern-not: ', 1)
            ending = b'\r\n' if line.endswith(b'\r\n') else b'\n'
            value = value.strip().replace(b'/', b'\\x2f')
            lines[index] = prefix + b'pattern-not: "' + value + b'"' + ending
    patched = b''.join(lines)
    if yaml.safe_load(patched) != yaml.safe_load(content):
        raise ValueError('Publication escaping changed rule semantics')
    return patched


def inventory(source):
    definitions, other = {}, []
    for file in sorted([*source.rglob('*.yml'), *source.rglob('*.yaml')]):
        if '.git' in file.relative_to(source).parts:
            continue
        if '.test.' in file.name or file.name.endswith(('.fixed.yaml', '.fixed.yml')):
            other.append(file.relative_to(source).as_posix())
            continue
        content = file.read_text(encoding='utf-8')
        if not re.search(r'^rules:\s*$', content, re.MULTILINE):
            other.append(file.relative_to(source).as_posix())
            continue
        data = yaml.safe_load(content)
        rules = data.get('rules') if isinstance(data, dict) else None
        if not isinstance(rules, list) or not rules or not all(isinstance(r, dict) and 'id' in r for r in rules):
            raise ValueError(f'Malformed rule definition: {file.relative_to(source)}')
        definitions[file.relative_to(source).as_posix()] = rules
    return definitions, other


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('source', type=Path)
    parser.add_argument('--import-rules', action='store_true')
    args = parser.parse_args()
    source = args.source.resolve(strict=True)
    actual = subprocess.check_output(['git', '-C', str(source), 'rev-parse', 'HEAD'], text=True).strip()
    if actual != COMMIT:
        raise ValueError('Expected pinned upstream checkout')
    definitions, other = inventory(source)
    changed = set(subprocess.check_output(['git', '-C', str(source), 'diff', '--name-only', 'HEAD'], text=True).splitlines())
    if (changed.intersection({*definitions, 'LICENSE', 'README.md'})
            or any(name.endswith(('.yml', '.yaml')) for name in changed)):
        raise ValueError('Upstream execution rules have local changes')
    rules = [r for rows in definitions.values() for r in rows]
    print(json.dumps(dict(commit=actual, files=len(definitions), rules=len(rules),
        languages=sorted({v for r in rules for v in r.get('languages', [])}),
        missing_languages=[r['id'] for r in rules if not r.get('languages')],
        duplicate_ids=sorted({r['id'] for r in rules if sum(x['id'] == r['id'] for x in rules)>1}),
        nonrule_files=len(other))))
    if not args.import_rules:
        return
    root = Path(__file__).resolve().parents[1]
    destination = root/'src/security_runtime/rules'
    if destination.exists():
        raise ValueError('Move the old rules directory aside before importing; never overwrite local changes')
    destination.mkdir()
    hashes = {}
    patches = {}
    for name in [*definitions, 'LICENSE', 'README.md']:
        target = destination/name
        target.parent.mkdir(parents=True, exist_ok=True)
        upstream = (source/name).read_bytes()
        content = publication_bytes(name, upstream)
        target.write_bytes(content)
        hashes[name] = hashlib.sha256(content).hexdigest()
        if content != upstream:
            patches[name] = dict(upstream_sha256=hashlib.sha256(upstream).hexdigest(),
                reason='YAML-equivalent escape of upstream dummy Slack URL; parsed rule unchanged')
    receipt = dict(repository='https://github.com/opengrep/opengrep-rules', commit=COMMIT,
                   license='LGPL-2.1-only WITH Commons-Clause', archived=True,
                   rule_files=len(definitions), rules=len(rules), sha256=hashes, local_patches=patches,
                   omitted_nonrule_yaml=other)
    (root/'src/security_runtime/opengrep_rules.json').write_text(
        json.dumps(receipt, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')


if __name__ == '__main__':
    main()
