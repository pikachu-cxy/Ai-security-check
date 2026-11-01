"""Compose trusted user-selected local rules using the existing pack validator."""
from contextlib import ExitStack
from contextvars import ContextVar
from pathlib import Path
import tempfile
import hashlib
import yaml

_resources = ContextVar('configured_rule_resources', default=None)


def resource_scope(stack):
    return _resources.set((stack, {}))


def end_scope(token):
    _resources.reset(token)


def sast_pack(manager):
    from .scan_preferences import section
    from .rulepacks import execution_rule
    config = section('rules', 'sast')
    if config['mode'] == 'builtin' and not config['exclude_ids']:
        return None
    resources = _resources.get()
    if resources is None:
        raise ValueError('Custom rules require a scan configuration scope')
    stack, cache = resources
    if 'sast' in cache:
        return cache['sast']
    packs = []
    if config['mode'] != 'replace':
        packs.append(manager.resolve(_configured=False))
    packs.extend(manager.resolve(user_path=Path(path), _configured=False) for path in config['paths'])
    directory = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix='ai-security-rules-'))).resolve()
    ids, excluded = set(), set(config['exclude_ids'])
    count = 0
    for pack in packs:
        for name in sorted({record.path for record in pack.catalog}):
            definitions = []
            for original in yaml.safe_load((pack.path/name).read_text(encoding='utf-8'))['rules']:
                rule = execution_rule(original, name, pack.descriptor)
                if rule['id'] in ids:
                    raise ValueError('Duplicate rule id in configured packs')
                ids.add(rule['id'])
                if rule['id'] not in excluded:
                    definitions.append(rule)
            if definitions:
                (directory/f'{count:06}.yaml').write_text(yaml.safe_dump({'rules': definitions}, sort_keys=False), encoding='utf-8')
                count += 1
    if excluded - ids:
        raise ValueError('Unknown excluded rule id')
    if not count:
        raise ValueError('Configured rules select no rules')
    pack = manager.resolve(user_path=directory, _configured=False)
    cache['sast'] = pack
    return pack


def gitleaks_config():
    from .scan_preferences import section
    from .scan_input import _read_file
    source = section('rules', 'gitleaks')['config_path']
    if not source:
        return None
    resources = _resources.get()
    if resources is None:
        raise ValueError('Custom configuration requires a scan configuration scope')
    stack, cache = resources
    if 'gitleaks' not in cache:
        # Reuse source integrity checks; TOML parser errors are not downgraded.
        import tomllib
        raw = _read_file(Path(source), 1_000_000)
        tomllib.loads(raw.decode('utf-8'))
        directory = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix='ai-security-gitleaks-'))).resolve()
        target = directory/'gitleaks.toml'
        target.write_bytes(raw)
        target.chmod(0o400)
        cache['gitleaks'] = (str(target), hashlib.sha256(raw).hexdigest())
    target, identity = cache['gitleaks']
    if hashlib.sha256(_read_file(Path(target), 1_000_000)).hexdigest() != identity:
        raise ValueError('Captured Gitleaks configuration changed')
    return target, identity
