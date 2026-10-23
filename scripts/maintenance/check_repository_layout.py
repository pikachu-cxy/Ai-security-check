"""Check repository references without importing scripts or executing snippets."""
from __future__ import annotations

import ast
from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[2]
NAVIGATION = ('docs/README.md', 'docs/guides/README.md', 'docs/design/README.md',
              'docs/NEXT_DEVELOPMENT_PLAN.zh-CN.md', 'docs/archive/2026-10/README.md',
              'docs/archive/2026-10/NEXT_DEVELOPMENT_PLAN.2026-10-22.zh-CN.md',
              'scripts/README.md', 'tests/README.md')


def runtime_import_errors(source: str, package: Path, location: str) -> list[str]:
    """Inspect ordinary Python and parseable embedded Python used by subprocesses."""
    errors = []
    seen = set()

    def inspect(text, label):
        if text in seen:
            return
        seen.add(text)
        try:
            tree = ast.parse(text)
        except SyntaxError:
            return  # Prose, shell snippets and partial templates are not Python.
        for node in ast.walk(tree):
            names = []
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and not node.level:
                names = [node.module or '']
                if node.module == 'security_runtime':
                    names += ['security_runtime.' + alias.name for alias in node.names
                              if alias.name != '*']
            for name in names:
                if not name.startswith('security_runtime.'):
                    continue
                path = package.joinpath(*name.split('.')[1:])
                if not path.with_suffix('.py').is_file() and not (path / '__init__.py').is_file():
                    errors.append(f'{label}:{node.lineno}: missing runtime module {name}')
            if isinstance(node, ast.Constant) and isinstance(node.value, str) and 'security_runtime' in node.value:
                inspect(node.value, f'{label}:embedded@{node.lineno}')

    inspect(source, location)
    return errors


def check(root: Path = ROOT) -> list[str]:
    errors = []
    for path in sorted((root / 'scripts').rglob('*.py')):
        errors += runtime_import_errors(path.read_text(encoding='utf-8-sig'),
                                       root / 'src/security_runtime', path.relative_to(root).as_posix())
    for path in sorted((root / '.github/workflows').glob('*.yml')):
        text = path.read_text(encoding='utf-8')
        for reference in sorted(set(re.findall(r'(?:scripts|tests)/[\w/.-]+\.py', text))):
            if not (root / reference).is_file():
                errors.append(f'{path.relative_to(root)}: missing entrypoint {reference}')
        for module in sorted(set(re.findall(r'python -m (scripts\.[\w.]+)', text))):
            if not root.joinpath(*module.split('.')).with_suffix('.py').is_file():
                errors.append(f'{path.relative_to(root)}: missing script module {module}')
    manifest = root / 'MANIFEST.in'
    for number, line in enumerate(manifest.read_text(encoding='utf-8').splitlines(), 1):
        parts = line.split()
        if parts and parts[0] == 'include':
            for pattern in parts[1:]:
                if not list(root.glob(pattern)):
                    errors.append(f'MANIFEST.in:{number}: missing include {pattern}')
        elif parts and parts[0] == 'recursive-include' and not (root / parts[1]).is_dir():
            errors.append(f'MANIFEST.in:{number}: missing directory {parts[1]}')
    for name in NAVIGATION:
        path = root / name
        if not path.is_file():
            errors.append(f'missing navigation {name}')
            continue
        for target in re.findall(r'\]\(([^\s)]+)\)', path.read_text(encoding='utf-8')):
            if re.match(r'^[a-zA-Z][\w+.-]*:', target) or target.startswith(('#', '/')):
                continue
            relative = target.partition('#')[0]
            if relative and not (path.parent / relative).exists():
                errors.append(f'{name}: missing link {target}')
    return errors


def main() -> int:
    errors = check()
    for error in errors:
        print(error)
    if not errors:
        print('Repository references OK')
    return int(bool(errors))


if __name__ == '__main__':
    raise SystemExit(main())
