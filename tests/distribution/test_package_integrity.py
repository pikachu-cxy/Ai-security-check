"""Release validation compares source identity, including after rule upgrades."""
from dataclasses import replace
from pathlib import Path
import runpy
import zipfile

import pytest

from security_runtime.rulepacks import RulePackManager

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def wheel(tmp_path):
    payload = {}
    source = ROOT / 'src/security_runtime'
    for file in source.rglob('*'):
        if file.is_file() and '__pycache__' not in file.parts:
            payload['security_runtime/' + file.relative_to(source).as_posix()] = file.read_bytes()
    prefix = 'ai_security_runtime-0.0.data/data/share/ai-security-runtime/'
    for name in ('LICENSE', 'EULA.md', 'LICENSING.md', 'LICENSES/Apache-2.0.txt',
                 'THIRD_PARTY_NOTICES.md', 'SOURCE_OFFER.md'):
        payload[prefix + name] = (ROOT / name).read_bytes()
    payload['ai_security_runtime-0.0.dist-info/METADATA'] = b'Name: ai-security-runtime\nVersion: 0.0\n'
    return tmp_path / 'fixture.whl', payload


def check_wheel(wheel):
    path, payload = wheel
    with zipfile.ZipFile(path, 'w') as archive:
        for name, data in payload.items():
            archive.writestr(name, data)
    runpy.run_path(str(ROOT / 'scripts/build/check_wheel.py'))['check'](path, ROOT)


def test_current_source_rule_inventory_is_accepted(wheel):
    check_wheel(wheel)


@pytest.mark.parametrize('changed', ['catalog-version', 'catalog-content', 'descriptor', 'rule-content'])
def test_stale_or_modified_rule_payload_cannot_pass_wheel_gate(wheel, changed):
    import json
    _, payload = wheel
    if changed.startswith('catalog'):
        name = 'security_runtime/opengrep_rules.json'
        catalog = json.loads(payload[name])
        if changed == 'catalog-version':
            catalog['commit'] = '0.0.0'
        else:
            catalog['sha256'].pop(next(iter(catalog['sha256'])))
        payload[name] = json.dumps(catalog).encode()
    else:
        name = ('security_runtime/rulepacks.py' if changed == 'descriptor'
                else 'security_runtime/' + next((ROOT/'src/security_runtime/rules').rglob('*.yaml')).relative_to(ROOT/'src/security_runtime').as_posix())
        payload[name] += b'\n# stale build content\n'
    with pytest.raises(ValueError, match='differs from source'):
        check_wheel(wheel)


def test_rule_release_contract_follows_validated_source_without_version_or_count_literals():
    contract = runpy.run_path(str(ROOT / 'scripts/build/verify_package.py'))['rule_contract']
    pack = RulePackManager().resolve()
    original = contract(pack)
    upgraded = replace(pack, descriptor=replace(pack.descriptor, version='99.1.0'),
                       checksum='a' * 64, catalog=pack.catalog[:-1])
    result = contract(upgraded)
    assert result['version'] == '99.1.0' and result['checksum'] == 'a' * 64
    assert len(result['catalog']) == len(original['catalog']) - 1
    assert original['version'] == pack.descriptor.version
    assert set(original['plans']) == {'app.py', 'app.js', 'view.jsx', 'app.ts', 'view.tsx'}


def test_install_verifier_passes_source_contract_to_isolated_interpreter(tmp_path, monkeypatch):
    import json
    from types import SimpleNamespace
    namespace = runpy.run_path(str(ROOT / 'scripts/build/verify_package.py'))
    main = namespace['main']
    commands = []
    contracts = []

    class ContractReached(Exception):
        pass

    def run(*command, cwd):
        commands.append(command)
        if command[1] == '-c':
            contract_path = Path(command[-1])
            assert contract_path.parent == cwd
            assert len(command[-1]) < 1000
            contracts.append(json.loads(contract_path.read_text(encoding='utf-8')))
            raise ContractReached()

    monkeypatch.setitem(main.__globals__, 'run', run)
    monkeypatch.setattr(namespace['venv'], 'EnvBuilder',
                        lambda **kwargs: SimpleNamespace(create=lambda path: None))
    # main scopes its environment changes to this test's monkeypatch context.
    monkeypatch.setenv('SECURITY_RUNTIME_STATE_DIR', str(tmp_path / 'state'))
    monkeypatch.setenv('SECURITY_RUNTIME_OFFLINE', '1')
    with pytest.raises(ContractReached):
        main(tmp_path / 'fixture.whl', offline=True)
    assert contracts == [namespace['rule_contract']()]
    assert '--no-index' in commands[0] and '--no-deps' in commands[0]
