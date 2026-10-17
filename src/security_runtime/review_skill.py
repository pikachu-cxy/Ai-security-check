"""User-scope Skill lifecycle; exact signed files, no Host config mutations."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
from pathlib import Path

from ._version import __version__
from .hook_state import HookStateStore, atomic_bytes, no_links
from .storage import SQLiteStore

NAME = 'ai-security-review'
CONTRACT = 'security-review-skill-v1'
MAX_BYTES = 256_000
BASE_FILES = {'SKILL.md', 'agents/openai.yaml', 'references/runtime-workflow.md'}


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode('utf-8')


def digest(content):
    return hashlib.sha256(content).hexdigest()


def skill_files():
    from .host_guidance import HOST_INSTRUCTIONS
    from .risk_decision_guidance import RISK_DECISION_GUIDANCE
    source = Path(__file__).parent / 'skills' / NAME
    return {name: (source / name).read_bytes() for name in (
        'SKILL.md', 'agents/openai.yaml', 'references/deep-audit.md', 'references/quick-task-review.md',
        'references/quick-task-review-v2.md', 'references/quick-task-review-v3.md')} | {
        'references/runtime-workflow.md': ('# Canonical Runtime workflow\n\n' + HOST_INSTRUCTIONS + '\n').encode('utf-8'),
        'references/risk-decisions.md': ('# 风险交互与用户处置\n\n' + RISK_DECISION_GUIDANCE).encode('utf-8')}


class ReviewSkillManager:
    def __init__(self, skills_dir=None, state_dir=None):
        # Current public Codex user Skill contract. Never modify config.toml.
        self.root = Path(os.path.abspath(Path(skills_dir) if skills_dir is not None
                                         else Path(os.getenv('SECURITY_RUNTIME_SKILLS_DIR', Path.home() / '.agents' / 'skills')))) / NAME
        self.state = (Path(state_dir) if state_dir is not None else
                      SQLiteStore.default_path().parent / 'review-skills') / digest(os.path.normcase(str(self.root)).encode())
        self.expected = skill_files()
        self.write_observer = None

    def write(self, path, content):
        if self.write_observer is not None:
            self.write_observer(path, content)
        if content is None:
            path.unlink(missing_ok=True)
        else:
            atomic_bytes(path, content)

    @staticmethod
    def read(path):
        no_links(path)
        if not path.exists(): return None
        if not path.is_file() or path.stat().st_size > MAX_BYTES:
            raise ValueError('SKILL_FILE_INVALID')
        with path.open('rb') as stream: content = stream.read(MAX_BYTES + 1)
        if len(content) > MAX_BYTES: raise ValueError('SKILL_FILE_TOO_LARGE')
        return content

    def manifest(self):
        raw = self.read(self.state / 'ownership.json')
        if raw is None: return None
        try:
            value = json.loads(raw)
            signature = value.pop('signature')
            key = self.read(self.state / 'ownership.key')
            if not key or len(key) != 32 or not hmac.compare_digest(signature,
                    hmac.new(key, encode(value), hashlib.sha256).hexdigest()): raise ValueError()
            if (value['contract'] != CONTRACT or value['scope'] != 'USER'
                    or value['skill'] != NAME or value['root_identity'] != self.state.name
                    or value['phase'] not in {'COMMITTED', 'UPDATING'}
                    or not BASE_FILES <= set(value['files']) <= set(self.expected)
                    or set(value.get('previous', {})) - set(self.expected)): raise ValueError()
            for content_hash in [*value['files'].values(), *value.get('previous', {}).values()]:
                if not isinstance(content_hash, str) or len(content_hash) != 64 or any(c not in '0123456789abcdef' for c in content_hash): raise ValueError()
            return value
        except (ValueError, TypeError, KeyError):
            raise ValueError('SKILL_OWNERSHIP_INVALID') from None

    def status(self):
        try:
            no_links(self.root)
            manifest = self.manifest()
            if manifest is None:
                state = 'USER_MANAGED' if self.root.exists() and any(self.root.iterdir()) else 'NOT_INSTALLED'
            else:
                modified = []
                missing = []
                for name, content_hash in manifest['files'].items():
                    raw = self.read(self.root / name)
                    if raw is None: missing.append(name)
                    elif digest(raw) not in {content_hash, manifest.get('previous', {}).get(name)}:
                        modified.append(name)
                # Adding a shipped file must not adopt content outside old ownership.
                for name in set(self.expected) - set(manifest['files']):
                    if self.read(self.root / name) is not None:
                        modified.append(name)
                state = ('USER_MODIFIED' if modified else 'REPAIR_REQUIRED' if missing or manifest['phase']=='UPDATING'
                         else 'INSTALLED' if manifest['files']=={n:digest(b) for n,b in self.expected.items()}
                         else 'UPGRADE_AVAILABLE')
            return {'skill':NAME, 'status':state, 'path':str(self.root),
                    'contract':CONTRACT, 'runtime_version':__version__,
                    'host_discovery':'HOST_MANAGED; restart if not visible'}
        except (OSError, ValueError):
            return {'skill':NAME, 'status':'OWNERSHIP_CONFLICT', 'reason':'SKILL_PATH_OR_OWNERSHIP_INVALID'}

    def save(self, value):
        key = self.read(self.state / 'ownership.key')
        if key is None:
            key = os.urandom(32)
            atomic_bytes(self.state / 'ownership.key', key)
        if len(key) != 32: raise ValueError('SKILL_OWNERSHIP_INVALID')
        self.write(self.state / 'ownership.json', encode(value | {
            'signature':hmac.new(key, encode(value), hashlib.sha256).hexdigest()}))

    def execute(self, action):
        if action not in {'install','status','upgrade','repair','remove'}: raise ValueError('Unknown Skill action')
        if action == 'status': return self.status()
        no_links(self.root)
        with HookStateStore(self.state / 'locks').lock(self.root, wait_seconds=0):
            before = self.status()
            if before['status'] in {'USER_MANAGED','USER_MODIFIED','OWNERSHIP_CONFLICT'}:
                return before | {'action':action,'changed':False,'reason':'USER_CONTENT_PRESERVED'}
            manifest = self.manifest()
            originals = {name:self.read(self.root / name) for name in self.expected}
            if action == 'remove':
                if manifest:
                    for name in manifest['files']:
                        raw = originals[name]
                        if raw is not None:
                            if self.read(self.root / name) != raw: raise ValueError('SKILL_CHANGED_DURING_UPDATE')
                            self.write(self.root / name, None)
                    for directory in ('agents','references',''):
                        try: (self.root / directory).rmdir()
                        except OSError: pass  # Never remove extra user files.
                    self.write(self.state / 'ownership.json', None)
                return {'skill':NAME,'status':'REMOVED','changed':bool(manifest), 'user_files_preserved':True}
            desired = {name:digest(raw) for name,raw in self.expected.items()}
            if before['status']=='INSTALLED': return before | {'action':action,'changed':False}
            value = {'skill':NAME,'contract':CONTRACT,'scope':'USER','root_identity':self.state.name,
                     'runtime_version':__version__,'phase':'UPDATING','files':desired,
                     'previous':{name:digest(raw) for name,raw in originals.items() if raw is not None}}
            self.save(value)
            for name, raw in self.expected.items():
                if self.read(self.root / name) != originals[name]: raise ValueError('SKILL_CHANGED_DURING_UPDATE')
                self.write(self.root / name,raw)
                if self.read(self.root / name) != raw: raise ValueError('SKILL_WRITE_FAILED')
            self.save(value | {'phase':'COMMITTED','previous':{}})
            return self.status() | {'action':action,'changed':True,'user_files_preserved':True}
