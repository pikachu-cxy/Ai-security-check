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


class FunctionalVerifierRegistry:
    def __init__(self):
        self.verifiers = (MavenVerifier(), GradleVerifier(), NodeVerifier(), PythonVerifier())

    def detect(self, root):
        return [s for verifier in self.verifiers for s in verifier.detect(root)]

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
                                 executable_hash=executable_hash,
                                 configs={n:hmac.new(key,config_bytes(root,n),hashlib.sha256).hexdigest()
                                          for n in step.config_files}))
        encoded = json.dumps(bindings,sort_keys=True,separators=(',',':')).encode()
        return dict(version=VERSION, detected_stack=sorted({s.provider for s in steps}),
                    steps=[s.public() for s in steps], config_hash=hmac.new(key,encoded,hashlib.sha256).hexdigest())
