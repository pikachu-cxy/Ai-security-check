"""Classification never executes command text or infers writes from queries."""
import pytest

from security_runtime.codex_event_adapter import classify_bash_command


@pytest.mark.parametrize('command', [
    'git status', 'git diff --stat', 'git diff -- src/a.py', 'git log --oneline', 'git show HEAD:src/a.py',
    'git -C "C:/project folder" --no-pager status --short',
    'git branch', 'git branch --list "feature/*"', 'git branch --show-current',
    'Get-Location', 'Get-ChildItem -Force | Select-Object Name,Mode',
    'Get-Content src/A.java', r'Get-Content src\A.java',
    'rg danger src', 'rg -n "copy|New-Item" src',
    "rg -n '$(Set-Content x y)|>output|`touch x`' src",
    'Get-Content README.md; rg -n "write" src',
    'git status && git diff --stat', 'git status || git diff --stat',
    'git status\nGet-Content README.md',
])
def test_complete_simple_read_commands_are_readonly(command):
    assert classify_bash_command({'cmd': command}) == 'READ_ONLY'


@pytest.mark.parametrize('command', [
    'git status; npm install',
    r'git diff; .venv\Scripts\python.exe scripts/generate.py',
    'Get-Content README.md; git checkout -- src/app.py',
    'git status | Unknown-Command', 'git status && make',
    'git branch feature', 'git branch -D feature', 'git branch --list --delete feature',
    'git branch --set-upstream-to=origin/main',
    'git diff --output=patch.txt', 'git log --out patch.txt',
    'git diff --ext-diff', 'git show --textconv HEAD:a.py',
    'git -c diff.external=generator diff',
    'rg --pre=generator pattern src', 'rg --pre generator pattern src',
    'rg --hostname-bin=generator --hyperlink-format=default pattern src',
    'rg *', 'git diff *', 'rg pattern [a-z]*',
    r'rg --p\re=generator pattern src', r'rg \--pre=generator pattern src',
    'rg "$(Set-Content x y)" src', 'rg $pattern src',
    'Get-Content README.md | ForEach-Object { Set-Content x $_ }',
    'rg `touch x` src', 'Get-Content $(Get-Item x)',
    'cat <(generate)', 'cat x > y', 'Get-Content x 2> errors.txt',
    'rg "unterminated', 'Get-Location; Copy-Item a b',
    'Get-Location; [IO.File]::WriteAllText("a", "b")',
    'Get-Location | Unknown-Command', '& Get-Content x',
])
def test_unknown_or_mutating_parts_never_bypass_reconciliation(command):
    assert classify_bash_command({'command': command}) != 'READ_ONLY'


@pytest.mark.parametrize('command', ['Set-Content x value', 'git status; Copy-Item a b', 'cat x > y'])
def test_known_write_shapes_keep_mutation_hint(command):
    assert classify_bash_command({'command': command}) == 'POSSIBLE_WORKSPACE_MUTATION'


@pytest.mark.parametrize('value', [None, {}, {'cmd': ''}, {'command': 7}, {'cmd': 'x' * 12001}])
def test_invalid_inputs_remain_unknown(value):
    assert classify_bash_command(value) == 'UNKNOWN'


@pytest.mark.parametrize('command', [
    'Get-Location; git rev-parse --show-toplevel; git branch --show-current; git status --short',
    'git rev-parse HEAD',
    'git rev-parse --path-format=absolute --git-common-dir',
    '$i=0; Get-Content billing/routes.py,billing/service.py | ForEach-Object { $_ }; rg -n "tenant_id|load_invoice" billing',
    'Get-Content a.py | ForEach-Object { $_ } | Select-Object -First 10',
])
def test_native_acceptance_readback_does_not_create_a_new_edit(command):
    assert classify_bash_command({'command': command}) == 'READ_ONLY'


@pytest.mark.parametrize('script', [
    'git diff --stat; git diff -- package.json package-lock.json src/adapters/render.js',
    '$i=0; Get-Content billing/routes.py | ForEach-Object { $_ }',
])
def test_verified_native_powershell_wrapper_preserves_readonly_classification(monkeypatch, script):
    import shlex
    monkeypatch.setattr('security_runtime.shell_classification._trusted_powershell', lambda path: True)
    command = '"C:/native/powershell/pwsh.exe" -NoProfile -Command ' + shlex.quote(script)
    assert classify_bash_command({'command': command}) == 'READ_ONLY'


@pytest.mark.parametrize('command', [
    '$env:PATH=0; Get-Content a.py',
    '$i=$(Set-Content x y); Get-Content a.py',
    'Get-Content a.py | ForEach-Object { $_; Set-Content x y }',
    'Get-Content a.py | ForEach-Object { & $_ }',
    'git rev-parse --git-dir; Copy-Item a b',
    'git rev-parse --git-path hooks; sh generator',
    '"C:/untrusted/pwsh.exe" -Command "git status"',
])
def test_readback_exceptions_do_not_hide_real_or_unknown_writes(command):
    assert classify_bash_command({'command': command}) != 'READ_ONLY'


@pytest.mark.parametrize('suffix', [
    "-EncodedCommand Z2l0IHN0YXR1cw==", "-File script.ps1", "-Command 'git status'; Set-Content x y",
    "-Command 'git status' -Command 'Set-Content x y'",
    "-Command 'git status; Set-Content x y'",
])
def test_wrapper_must_not_ignore_extra_commands(monkeypatch, suffix):
    monkeypatch.setattr('security_runtime.shell_classification._trusted_powershell', lambda path: True)
    assert classify_bash_command({'command': '"C:/native/powershell/pwsh.exe" '+suffix}) != 'READ_ONLY'
