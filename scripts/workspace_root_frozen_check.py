"""Read-only package identity and pure path checks; no scan or Hook dispatch.

PYZ entries are unmarshaled and hashed as CodeType data. They are never executed,
imported, or used to construct callable functions. Target projects are inspected
only through root resolution (directory/marker metadata and Git top-level).
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys
import time
from types import CodeType

from PyInstaller.archive.readers import CArchiveReader


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from security_runtime.global_workspace import resolve_workspace


def constant(value):
    if isinstance(value, CodeType):
        return {'type': 'code', 'value': canonical_code(value)}
    if value is None or value is Ellipsis:
        return {'type': type(value).__name__, 'value': repr(value)}
    if isinstance(value, bytes):
        return {'type': 'bytes', 'value': value.hex()}
    if isinstance(value, (str, bool, int)):
        return {'type': type(value).__name__, 'value': value}
    if isinstance(value, float):
        return {'type': 'float', 'value': value.hex()}
    if isinstance(value, complex):
        return {'type': 'complex', 'value': [value.real.hex(), value.imag.hex()]}
    if isinstance(value, (tuple, frozenset)):
        children = [constant(item) for item in value]
        if isinstance(value, frozenset):
            children.sort(key=lambda item: json.dumps(item, sort_keys=True, separators=(',', ':')))
        return {'type': type(value).__name__, 'value': children}
    raise TypeError(f'Unsupported code constant type: {type(value).__name__}')


def canonical_code(code):
    # File paths, first-line offsets and source-line tables are intentionally
    # excluded. Nested generators/code constants retain their actual semantics.
    return {
        'name': code.co_name, 'qualname': code.co_qualname,
        'argcount': code.co_argcount, 'posonlyargcount': code.co_posonlyargcount,
        'kwonlyargcount': code.co_kwonlyargcount, 'nlocals': code.co_nlocals,
        'stacksize': code.co_stacksize, 'flags': code.co_flags,
        'code': code.co_code.hex(), 'consts': [constant(value) for value in code.co_consts],
        'names': list(code.co_names), 'varnames': list(code.co_varnames),
        'freevars': list(code.co_freevars), 'cellvars': list(code.co_cellvars),
        'exceptiontable': code.co_exceptiontable.hex(),
    }


def code_hash(code):
    return hashlib.sha256(json.dumps(canonical_code(code), sort_keys=True,
                                    separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()


def find_function(module_code, name):
    matches = [value for value in module_code.co_consts
               if isinstance(value, CodeType) and value.co_name == name]
    if len(matches) != 1:
        raise ValueError('Expected one direct module function')
    return matches[0]


def frozen_function_hash(executable):
    archive = CArchiveReader(str(executable))
    names = [name for name, entry in archive.toc.items() if entry[-1] == 'z']
    if len(names) != 1:
        raise ValueError('Expected one embedded PYZ archive')
    pyz = archive.open_embedded_archive(names[0])
    module_code = pyz.extract('security_runtime.global_workspace')
    if not isinstance(module_code, CodeType):
        raise TypeError('PYZ entry is not CodeType data')
    return code_hash(find_function(module_code, 'resolve_workspace'))


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def resource_proof(package):
    files = (
        ('dynamic_function_implementation', 'src/security_runtime/dynamic_function.py',
         '_internal/security_runtime/dynamic_function.py'),
        ('arithmetic_regression', 'src/security_runtime/assets/arithmetic_regression.mjs',
         '_internal/security_runtime/assets/arithmetic_regression.mjs'),
        ('arithmetic_regression_worker', 'src/security_runtime/assets/arithmetic_regression_worker.mjs',
         '_internal/security_runtime/assets/arithmetic_regression_worker.mjs'),
    )
    rows = []
    for label, source_name, frozen_name in files:
        source, frozen = ROOT / source_name, package / frozen_name
        row = {'resource': label, 'source_path': str(source), 'frozen_path': str(frozen),
               'source_exists': source.is_file(), 'frozen_exists': frozen.is_file()}
        row['source_sha256'] = digest(source) if row['source_exists'] else None
        row['frozen_sha256'] = digest(frozen) if row['frozen_exists'] else None
        row['matches'] = bool(row['source_sha256'] and row['source_sha256'] == row['frozen_sha256'])
        rows.append(row)
    return rows


def path_proof(container):
    inner = container / 'FlyCRM-AI-feat-ai-chat'
    copy = container / 'hook-experience-r6'
    cases = (
        ('outer_wrapper_rejected', container, None),
        ('inner_root', inner, inner),
        ('inner_src', inner / 'src', inner),
        ('inner_src_crm', inner / 'src/crm', inner),
        ('git_copy_root', copy, copy),
        ('git_copy_src', copy / 'src', copy),
        ('git_copy_src_crm', copy / 'src/crm', copy),
    )
    rows = []
    for label, candidate, expected in cases:
        started = time.perf_counter()
        row = {'case': label, 'candidate': str(candidate),
               'expected_root': str(expected) if expected else None}
        try:
            resolved = resolve_workspace(candidate)
            row.update(status='RESOLVED', resolved_root=str(resolved),
                       passed=expected is not None and resolved == expected.resolve(strict=True))
        except ValueError as exc:
            row.update(status='REJECTED', resolved_root=None,
                       reason=str(exc).splitlines()[0], passed=expected is None)
        except OSError as exc:
            row.update(status='IO_ERROR', resolved_root=None,
                       reason=type(exc).__name__, passed=False)
        row['duration_ms'] = round((time.perf_counter() - started) * 1000, 3)
        rows.append(row)
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--executable', type=Path, required=True)
    parser.add_argument('--previous-executable', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--expected-build-id')
    parser.add_argument('--fly-container', type=Path,
                        default=Path(r'C:\Users\24170\Downloads\FlyCRM-AI-feat-ai-chat'))
    args = parser.parse_args()
    package = args.executable.resolve(strict=True).parent
    version_path = package / 'version.json'
    version = json.loads(version_path.read_text(encoding='utf-8'))
    source_path = ROOT / 'src/security_runtime/global_workspace.py'
    # compile produces inert code data; no eval/exec or archived function call.
    source_code = compile(source_path.read_bytes(), str(source_path), 'exec',
                          dont_inherit=True, optimize=0)
    source_hash = code_hash(find_function(source_code, 'resolve_workspace'))
    frozen_hash = frozen_function_hash(args.executable)
    previous_hash = frozen_function_hash(args.previous_executable)
    resources = resource_proof(package)
    paths = path_proof(args.fly_container)
    checks = {
        'frozen_function_matches_current_source': frozen_hash == source_hash,
        'frozen_function_differs_from_previous_installed': frozen_hash != previous_hash,
        'required_implementation_and_assets_match': all(row['matches'] for row in resources),
        'all_path_diagnostics_pass': all(row['passed'] for row in paths),
        'expected_build_id_matches': args.expected_build_id is None or version['build_id'] == args.expected_build_id,
    }
    proof = {
        'status': 'PASSED' if all(checks.values()) else 'FAILED',
        'evidence_kind': 'READ_ONLY_PACKAGE_IDENTITY_AND_SOURCE_PATH_DIAGNOSTICS',
        'build_id': version['build_id'], 'version': version['version'],
        'executable': str(args.executable.resolve(strict=True)),
        'previous_executable': str(args.previous_executable.resolve(strict=True)),
        'source_resolve_workspace_code_sha256': source_hash,
        'frozen_resolve_workspace_code_sha256': frozen_hash,
        'previous_resolve_workspace_code_sha256': previous_hash,
        'hash_policy': 'Recursive CodeType bytecode/constants/names/flags/exception tables; filename and source-line metadata excluded.',
        'archive_bytecode_executed': False, 'scanner_run': False, 'hook_dispatch': False,
        'target_project_source_contents_read': False, 'environment_or_key_files_read': False,
        'security_proof': False, 'checks': checks, 'resources': resources, 'paths': paths,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(proof, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    print(json.dumps({'status': proof['status'], 'build_id': proof['build_id'],
                      'checks': checks, 'output': str(args.output)}, ensure_ascii=False))
    return 0 if proof['status'] == 'PASSED' else 1


if __name__ == '__main__':
    raise SystemExit(main())
