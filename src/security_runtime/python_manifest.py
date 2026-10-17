"""Read Python declarations without executing project code or resolving packages.

Generated requirements exist only inside the scanner's private snapshot. Findings
and inventory always refer back to the original pyproject.toml.
"""
from __future__ import annotations

from pathlib import Path
import tempfile
import tomllib

from packaging.requirements import Requirement, InvalidRequirement
from packaging.version import Version, InvalidVersion


def declarations(path: Path) -> tuple[list[str], dict]:
    with path.open('rb') as stream:
        raw = stream.read(1_000_001)
    if len(raw) > 1_000_000:
        raise ValueError('Python dependency manifest exceeds the bounded size')
    try:
        data = tomllib.loads(raw.decode('utf-8-sig'))
    except (UnicodeError, tomllib.TOMLDecodeError):
        raise ValueError('Python dependency manifest is not valid UTF-8 TOML') from None
    project = data.get('project', {})
    build = data.get('build-system', {})
    if not isinstance(project, dict) or not isinstance(build, dict):
        raise ValueError('Python dependency declaration has an invalid structure')
    groups = [project.get('dependencies', []), build.get('requires', [])]
    optional = project.get('optional-dependencies', {})
    if not isinstance(optional, dict):
        raise ValueError('Python optional dependency groups must be tables')
    groups.extend(optional.values())
    if any(not isinstance(group, list) for group in groups):
        raise ValueError('Python dependency groups must be arrays')
    entries = [entry for group in groups for entry in group]
    if len(entries) > 2000 or any(not isinstance(entry, str) or len(entry) > 4096 for entry in entries):
        raise ValueError('Python dependency declarations exceed the bounded format')
    dynamic = project.get('dynamic', [])
    if not isinstance(dynamic, list) or any(not isinstance(item, str) for item in dynamic):
        raise ValueError('Python dynamic declaration must be an array')
    unresolved = int(bool({'dependencies', 'optional-dependencies'} & set(x for x in dynamic if isinstance(x, str))))
    # Unsupported Poetry/dependency-group declarations are explicit gaps, never
    # silently interpreted as an empty, checked project.
    tool = data.get('tool', {})
    if isinstance(tool, dict) and isinstance(tool.get('poetry'), dict):
        unresolved += int(any(key in tool['poetry'] for key in ('dependencies', 'group', 'dev-dependencies')))
    unresolved += int(bool(data.get('dependency-groups')))
    pinned = set()
    conditional = 0
    for entry in entries:
        try:
            req = Requirement(entry)
            specs = list(req.specifier)
            if req.url or len(specs) != 1 or specs[0].operator != '==' or '*' in specs[0].version:
                unresolved += 1
                continue
            version = str(Version(specs[0].version))
            pinned.add(f'{req.name}=={version}')
            # Do not evaluate markers using the build host's environment. Check
            # all declared exact versions, including conditional/optional ones.
            conditional += int(req.marker is not None or bool(req.extras))
        except (InvalidRequirement, InvalidVersion):
            unresolved += 1
    return sorted(pinned), {'declared_entries': len(entries), 'exact_versions': len(pinned),
        'unresolved_entries': unresolved, 'conditional_entries': conditional,
        'scope': 'DECLARED_VERSIONS_ONLY'}


def stage_python_manifests(snapshot: Path, files) -> tuple[dict[str, str], dict[str, dict]]:
    aliases, reports = {}, {}
    for name in files:
        if Path(name).name != 'pyproject.toml':
            continue
        requirements, report = declarations(snapshot / name)
        reports[name] = report
        if requirements:
            directory = Path(tempfile.mkdtemp(prefix='.runtime-python-', dir=snapshot))
            generated = directory / 'requirements.txt'
            generated.write_text('\n'.join(requirements) + '\n', encoding='utf-8')
            aliases[generated.relative_to(snapshot).as_posix()] = name
    return aliases, reports


def manifest_target(value: str, snapshot: Path, aliases: dict[str, str]) -> str:
    target = Path(value.replace('\\', '/'))
    if target.is_absolute():
        target = target.resolve().relative_to(snapshot.resolve())
    relative = target.as_posix()
    if '..' in target.parts:
        raise ValueError('Dependency output escaped the planned snapshot')
    return aliases.get(relative, relative)
