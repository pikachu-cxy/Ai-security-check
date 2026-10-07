"""Deterministic local verifier catalog. Project text is data, never instructions."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
from typing import Protocol

from .hook_state import no_links

VERSION = 'functional-verification-v0.1'
MAX_CONFIG = 65536


def config_bytes(root, name):
    path = root / name
    no_links(path)
    if not path.is_file() or path.stat().st_size > MAX_CONFIG:
        raise ValueError('CONFIG_UNAVAILABLE_OR_TOO_LARGE')
    data = path.read_bytes()
    if len(data) > MAX_CONFIG:
        raise ValueError('CONFIG_UNAVAILABLE_OR_TOO_LARGE')
    return data


@dataclass(frozen=True)
class Step:
    kind: str
    provider: str
    command_id: str
    executable: str | None
    arguments: tuple[str, ...]
    config_files: tuple[str, ...]
    wrapper: bool = False
    target_files: tuple[str, ...] = ()

    def public(self):
        return dict(kind=self.kind, provider=self.provider, command_id=self.command_id,
                    working_directory='.', network_allowed=False, wrapper=self.wrapper,
                    available=self.executable is not None)

    def argv(self):
        # Only detector-created IDs/argv reach the executor. Not an MCP field.
        if not self.executable:
            raise ValueError('LOCAL_TOOL_UNAVAILABLE')
        return [self.executable, *self.arguments]


class FunctionalVerifier(Protocol):
    def detect(self, root: Path) -> list[Step]: ...


def tool(root, wrappers, system):
    for name in wrappers:
        if (root / name).exists():
            config_bytes(root, name)
            return './' + name, True, (name,)
    return shutil.which(system), False, ()


class MavenVerifier:
    def detect(self, root):
        if not (root / 'pom.xml').exists(): return []
        config_bytes(root, 'pom.xml')
        exe, wrapper, configs = tool(root, ('mvnw.cmd', 'mvnw') if os.name == 'nt' else ('mvnw',), 'mvn')
        configs += ('pom.xml',)
        goals=[('BUILD','compile',('-DskipTests',))]
        if (root/'src/test').is_dir() and any((root/'src/test').rglob('*.java')):
            goals.append(('TEST','test',('-DfailIfNoTests=true',)))
        return [Step(kind, 'maven', 'maven-' + goal, exe,
                     ('-o', '-B', '-q', *flags, goal), configs, wrapper)
                for kind, goal, flags in goals]


class GradleVerifier:
    def detect(self, root):
        configs = tuple(n for n in ('build.gradle', 'build.gradle.kts') if (root / n).exists())
        if not configs: return []
        for n in configs: config_bytes(root, n)
        exe, wrapper, wrappers = tool(root, ('gradlew.bat', 'gradlew') if os.name == 'nt' else ('gradlew',), 'gradle')
        goals=[('BUILD','classes')]
        if (root/'src/test').is_dir() and any(p.suffix in {'.java','.kt','.groovy'} for p in (root/'src/test').rglob('*')):
            goals.append(('TEST','test'))
        return [Step(kind,'gradle','gradle-' + goal,exe,
                     ('--offline','--no-daemon','--console=plain',goal),configs + wrappers,wrapper)
                for kind,goal in goals]


class NodeVerifier:
    def detect(self, root):
        if not (root / 'package.json').exists(): return []
        data = json.loads(config_bytes(root,'package.json'))
        if not isinstance(data,dict) or not isinstance(data.get('scripts',{}),dict):
            raise ValueError('INVALID_PACKAGE_METADATA')
        scripts = data.get('scripts',{})
        # Manager choice is deterministic. Never run npx/corepack/downloads.
        lock = next((n for n in ('pnpm-lock.yaml','yarn.lock','package-lock.json') if (root/n).exists()),None)
        manager = {'pnpm-lock.yaml':'pnpm','yarn.lock':'yarn'}.get(lock,'npm')
        exe = shutil.which(manager)
        configs = ('package.json',) + ((lock,) if lock else ())
        for name in configs: config_bytes(root,name)
        return [Step(kind,'node',f'{manager}-{name}',exe,
                     ('--offline','run',name) if manager != 'npm' else ('--offline','--ignore-scripts','run',name), configs)
                for name,kind in [('typecheck','TYPECHECK'),('test','TEST'),('lint','LINT'),('build','BUILD')]
                if isinstance(scripts.get(name),str) and scripts[name].strip()]


class PythonVerifier:
    def detect(self,root):
        configs = tuple(n for n in ('pyproject.toml','pytest.ini','setup.cfg') if (root/n).exists())
        requirements = sorted(p.name for p in root.glob('requirements*.txt'))[:16]
        if not configs and not requirements: return []
        for n in (*configs,*requirements): config_bytes(root,n)
        # Require actual tests and existing configuration, never install pytest.
        if not configs or not (root/'tests').is_dir(): return []
        import importlib.util
        exe = sys.executable if importlib.util.find_spec('pytest') and not getattr(sys,'frozen',False) else None
        return [Step('TEST','python','python-pytest',exe,('-m','pytest','-q','--no-header','tests'),configs)]

    def detect_host(self, root, selected):
        configs = tuple(n for n in ('pyproject.toml', 'pytest.ini', 'setup.cfg') if (root / n).exists())
        for name in configs:
            config_bytes(root, name)
        candidates = [str(Path('tests') / ('test_' + Path(n).stem + '.py')) for n in selected]
        related = tuple(n for n in candidates if (root / n).is_file())
        entrances = related or (('tests',) if (root / 'tests').is_dir() else
                               tuple(sorted(p.name for p in root.glob('test_*.py'))))
        if not entrances:
            return []
        import importlib.util
        exe = sys.executable if importlib.util.find_spec('pytest') and not getattr(sys, 'frozen', False) else None
        return [Step('TEST', 'python', 'python-pytest', exe,
                     ('-m', 'pytest', '-q', '--no-header', '-p', 'no:cacheprovider', *entrances), configs,
                     target_files=selected)]


def targets(root, names):
    """Only Runtime-selected relative members; never shell fragments or links."""
    result = []
    for name in names:
        if (not isinstance(name, str) or not name or len(name) > 1024 or
                any(ord(c) < 32 for c in name) or '\\' in name or
                any(c in name for c in ';|&`$<>"') or
                Path(name).is_absolute() or '..' in Path(name).parts or name.startswith('-')):
            raise ValueError('VERIFIER_SCOPE_REJECTED')
        path = root / name
        no_links(path)
        if not path.resolve().is_relative_to(root.resolve()) or not path.is_file():
            raise ValueError('VERIFIER_SCOPE_REJECTED')
        result.append(Path(name).as_posix())
    if not result or len(result) > 8:
        raise ValueError('VERIFIER_SCOPE_REJECTED')
    return tuple(sorted(set(result)))


class JavacVerifier:
    def detect(self, root, target_files):
        selected = targets(root, target_files)
        if not all(n.endswith('.java') for n in selected):
            return []
        # Output/classpath/sourcepath are supplied by the host-plan builder,
        # using a Runtime-owned empty directory outside the project.
        return [Step('COMPILE', 'javac', 'java-javac-target', shutil.which('javac'),
                     ('-proc:none', '-implicit:none', '-encoding', 'UTF-8'), (),
                     target_files=selected)]


class GoVerifier:
    def detect(self, root):
        if not (root / 'go.mod').exists():
            return []
        config_bytes(root, 'go.mod')
        if not any(root.rglob('*_test.go')):
            return []
        return [Step('TEST', 'go', 'go-test', shutil.which('go'), ('test', './...'), ('go.mod',))]


class FunctionalVerifierRegistry:
    def __init__(self):
        self.verifiers = (MavenVerifier(), GradleVerifier(), NodeVerifier(), PythonVerifier())

    def detect(self, root, target_files=None):
        if target_files is None:
            # Original internal detector API remains compatible.
            return [s for verifier in self.verifiers for s in verifier.detect(root)]
        selected = targets(root, target_files)
        if all(n.endswith('.java') for n in selected):
            # Existing build metadata wins even when its tool is unavailable.
            for verifier in (MavenVerifier(), GradleVerifier()):
                steps = verifier.detect(root)
                if steps:
                    return steps
            return JavacVerifier().detect(root, selected)
        if all(n.endswith('.go') for n in selected):
            steps = GoVerifier().detect(root)
            package = sorted({str(Path(n).parent).replace('\\', '/') for n in selected})
            if steps:
                step = steps[0]
                return [Step(step.kind, step.provider, step.command_id, step.executable,
                             ('test', *('./' + n if n != '.' else '.' for n in package)), step.config_files,
                             target_files=selected)]
            return []
        if all(n.endswith('.py') for n in selected):
            return PythonVerifier().detect_host(root, selected)
        if all(Path(n).suffix in {'.js', '.jsx', '.ts', '.tsx', '.vue'} for n in selected):
            return NodeVerifier().detect(root)
        return [s for verifier in (NodeVerifier(), PythonVerifier()) for s in verifier.detect(root)]

    def plan(self, root, steps, key):
        import hmac
        bindings = []
        for step in steps:
            executable_hash=None
            if step.executable and not step.wrapper:
                executable=Path(step.executable)
                if executable.is_file():
                    if executable.stat().st_size>32_000_000: raise ValueError('LOCAL_TOOL_IDENTITY_BUDGET')
                    executable_hash=hashlib.sha256(executable.read_bytes()).hexdigest()
            bindings.append(dict(step=step.public(), executable=step.executable, arguments=step.arguments,
                                 target_files=step.target_files,
                                 executable_hash=executable_hash,
                                 configs={n:hmac.new(key,config_bytes(root,n),hashlib.sha256).hexdigest()
                                          for n in step.config_files}))
        encoded = json.dumps(bindings,sort_keys=True,separators=(',',':')).encode()
        return dict(version=VERSION, detected_stack=sorted({s.provider for s in steps}),
                    steps=[s.public() for s in steps], config_hash=hmac.new(key,encoded,hashlib.sha256).hexdigest())
