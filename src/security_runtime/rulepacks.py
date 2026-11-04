"""Rule packs have their own provenance, licensing and lifecycle."""
from __future__ import annotations

from .performance_trace import timed

import hashlib
import threading
import json
from dataclasses import asdict, dataclass
from enum import StrEnum
from pathlib import Path
from typing import Protocol
from .hook_state import native_io_path
from .rule_catalog import RuleRecord, validate_rule, load_catalog
from .rule_program import RuleProgram, load_program

import yaml

# LibYAML uses the same safe constructors without Python tokenization overhead.
_SAFE_LOADER = getattr(yaml, "CSafeLoader", yaml.SafeLoader)


class RulePackClass(StrEnum):
    FIRST_PARTY = "FIRST_PARTY"
    PERMISSIVE_THIRD_PARTY = "PERMISSIVE_THIRD_PARTY"
    ENTERPRISE = "ENTERPRISE"
    USER_PROVIDED = "USER_PROVIDED"
    RESTRICTED = "RESTRICTED"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class RuleProvenance:
    origin: str
    author: str
    created_at: str
    references: tuple[str, ...]
    license: str
    derived_from: str | None = None


@dataclass(frozen=True)
class RulePackDescriptor:
    rule_pack_id: str
    display_name: str
    version: str
    publisher: str
    copyright: str
    license: str
    license_url: str
    commercial_use_allowed: bool
    redistribution_allowed: bool
    hosted_service_allowed: bool
    modification_allowed: bool
    source: str
    provenance: RuleProvenance
    bundled: bool
    pack_class: RulePackClass


@dataclass(frozen=True)
class ResolvedRulePack:
    descriptor: RulePackDescriptor
    path: Path
    checksum: str
    catalog: tuple[RuleRecord, ...] = ()
    program: RuleProgram | None = None


class RulePackProvider(Protocol):
    def discover(self) -> list[ResolvedRulePack]: ...
    @timed("rules.resolve")
    def resolve(self, rule_pack_id: str) -> ResolvedRulePack: ...


class RulePackUpdateProvider(RulePackProvider, Protocol):
    """Future signed updates must verify before activation and allow rollback."""

    def stage(self, rule_pack_id: str, version: str, checksum: str, signature: bytes) -> ResolvedRulePack: ...
    def activate(self, candidate: ResolvedRulePack) -> None: ...
    def rollback(self, rule_pack_id: str, version: str) -> None: ...


OPENGREP_RULES_COMMIT = 'f1d2b562b414783763fd02a6ed2736eaed622efa'
DEFAULT_RULE_PACK = RulePackDescriptor(
    'opengrep-rules', 'OpenGrep Rules', OPENGREP_RULES_COMMIT, 'OpenGrep / upstream contributors',
    'Copyright Semgrep, Inc. and rule contributors', 'LGPL-2.1-only WITH Commons-Clause',
    'https://github.com/opengrep/opengrep-rules/blob/'+OPENGREP_RULES_COMMIT+'/LICENSE',
    False, True, False, True, 'https://github.com/opengrep/opengrep-rules/tree/'+OPENGREP_RULES_COMMIT,
    RuleProvenance('THIRD_PARTY', 'Semgrep and rule contributors', '2024-12-13',
                   ('https://github.com/opengrep/opengrep-rules',), 'LGPL-2.1-only WITH Commons-Clause'),
    True, RulePackClass.RESTRICTED)
# Import compatibility only. This no longer denotes a first-party pack.
FIRST_PARTY_RULE_PACK = DEFAULT_RULE_PACK


def execution_rule(rule, relative, descriptor):
    """Namespace upstream occurrences without modifying the vendored YAML."""
    if descriptor.rule_pack_id != 'opengrep-rules':
        return rule
    value = dict(rule)
    value['id'] = str(Path(relative).with_suffix('')).replace('\\', '.').replace('/', '.')+'.'+rule['id']
    return value


def can_bundle_rule_pack(descriptor: RulePackDescriptor) -> bool:
    # Explicit product scope: pinned upstream pack for the free personal
    # distribution. This exception does NOT assert commercial/SaaS rights.
    if descriptor == DEFAULT_RULE_PACK:
        return True
    return bool(descriptor.bundled and descriptor.pack_class in {RulePackClass.FIRST_PARTY, RulePackClass.PERMISSIVE_THIRD_PARTY}
                and descriptor.commercial_use_allowed and descriptor.redistribution_allowed and descriptor.hosted_service_allowed)


class BundledRulePackProvider:
    def __init__(self, path: Path | None = None):
        self.path = path or Path(__file__).parent / "rules"

    def discover(self) -> list[ResolvedRulePack]:
        return [self.resolve(FIRST_PARTY_RULE_PACK.rule_pack_id)]

    @timed("rules.resolve")
    def resolve(self, rule_pack_id: str) -> ResolvedRulePack:
        if rule_pack_id != FIRST_PARTY_RULE_PACK.rule_pack_id:
            raise KeyError(rule_pack_id)
        return RulePackManager._validate(DEFAULT_RULE_PACK, self.path, require_first_party_metadata=False)


class RulePackManager:
    def __init__(self, provider: RulePackProvider | None = None):
        self.provider = provider or BundledRulePackProvider()
        self._resolved_cache = {}  # Validated metadata only, never scan evidence.
        self._cache_lock = threading.RLock()
        self.cache_hit = False

    @staticmethod
    @timed("rules.content_identity")
    def _content_identity(path):
        path = path.expanduser().resolve()
        io_root = native_io_path(path)
        if not io_root.is_dir():
            raise ValueError('Rule pack directory is missing')
        files = sorted(io_root.rglob('*.yml')) + sorted(io_root.rglob('*.yaml'))
        if not files or len(files) > 10000:
            raise ValueError('Rule pack file budget exceeded')
        files += [p for p in (io_root/'catalog.json',io_root/'capabilities.json',io_root/'LICENSE',io_root/'NOTICE') if p.is_file()]
        digest = hashlib.sha256()
        for file in files:
            if file.is_symlink() or file.is_junction() or file.stat().st_size > 1_000_000:
                raise ValueError('Invalid rule pack input')
            digest.update(file.relative_to(io_root).as_posix().encode());digest.update(file.read_bytes())
        return str(path),digest.digest()

    def _cached_resolve(self, descriptor, path, **kwargs):
        from .scanner_cache import preparation_bucket, workspace_key
        bucket = preparation_bucket('rule_pack')
        self._resolved_cache, self._cache_lock = bucket.values, bucket.lock
        with self._cache_lock:
            key = (workspace_key(), repr(descriptor), self._content_identity(path), tuple(sorted(kwargs.items())))
            self.cache_hit = key in self._resolved_cache
            if self.cache_hit:
                return self._resolved_cache[key]
            result = self._validate(descriptor, path, content_identity=key[2][1], **kwargs)
            io_root = native_io_path(path)
            size=sum(p.stat().st_size for p in (*io_root.rglob('*.yml'),*io_root.rglob('*.yaml')))
            if len(result.catalog)<=10000 and size<=32_000_000:
                if len(self._resolved_cache) >= 8:
                    self._resolved_cache.pop(next(iter(self._resolved_cache)))
                self._resolved_cache[key] = result
            return result

    def discover(self) -> list[ResolvedRulePack]:
        return self.provider.discover()

    @timed("rules.resolve")
    def resolve(self, rule_pack_id: str = "opengrep-rules", *, user_path: Path | None = None, _configured=True) -> ResolvedRulePack:
        if user_path is None and _configured:
            from .configured_rules import sast_pack
            custom = sast_pack(self)
            if custom is not None:
                return custom
        if user_path is None:
            if type(self.provider) is BundledRulePackProvider:
                if rule_pack_id != FIRST_PARTY_RULE_PACK.rule_pack_id:
                    raise KeyError(rule_pack_id)
                return self._cached_resolve(DEFAULT_RULE_PACK,self.provider.path, require_first_party_metadata=False)
            self.cache_hit = False  # External providers retain their lifecycle.
            return self.provider.resolve(rule_pack_id)
        descriptor = RulePackDescriptor(
            "user-provided", "User provided rules", "unversioned", "User", "User owned", "User provided",
            "", False, False, False, False, str(user_path),
            RuleProvenance("USER_PROVIDED", "User", "", (), "User provided"), False, RulePackClass.USER_PROVIDED)
        # The caller owns these rules. We validate local scope, never copy them.
        return self._cached_resolve(descriptor, user_path, require_first_party_metadata=False)

    def bind_input(self, pack: ResolvedRulePack, path: Path) -> ResolvedRulePack:
        """Validate captured bytes while retaining the actual rule provenance."""
        captured = self._validate(pack.descriptor, path,
            require_first_party_metadata=pack.program is not None)
        if captured.checksum != pack.checksum:
            raise ValueError('Rule pack changed during input capture')
        return captured

    @staticmethod
    @timed("rules.validate")
    def _validate(descriptor: RulePackDescriptor, path: Path, *, require_first_party_metadata: bool = True,
                  content_identity: bytes | None = None) -> ResolvedRulePack:
        # First-party capability programs retain their existing validation path.
        if require_first_party_metadata:
            return RulePackManager._validate_uncached(descriptor, path,
                require_first_party_metadata=True)
        from .preparation_cache import PreparationCache
        cache = PreparationCache()
        # The caller already read these bytes to select the process cache entry.
        content = content_identity if content_identity is not None else RulePackManager._content_identity(path)[1]
        key = (repr(descriptor), content)
        saved = cache.get('rule-pack', key)
        if saved is not None:
            catalog = tuple(RuleRecord(**{k: tuple(v) if isinstance(v, list) else v
                for k, v in row.items()}) for row in saved['catalog'])
            return ResolvedRulePack(descriptor, path.expanduser().resolve(), saved['checksum'], catalog)
        result = RulePackManager._validate_uncached(descriptor, path,
            require_first_party_metadata=False)
        if RulePackManager._content_identity(path)[1] != content:
            raise ValueError('Rule pack changed during validation')
        cache.put('rule-pack', key, dict(checksum=result.checksum,
            catalog=[asdict(rule) for rule in result.catalog]))
        return result

    @staticmethod
    def _validate_uncached(descriptor: RulePackDescriptor, path: Path, *, require_first_party_metadata: bool) -> ResolvedRulePack:
        path = path.expanduser().resolve()
        io_root = native_io_path(path)
        if not io_root.is_dir():
            raise ValueError("Rule pack directory is missing")
        if descriptor.bundled and not can_bundle_rule_pack(descriptor):
            raise ValueError("Rule pack license blocks bundling")
        if descriptor.bundled and not native_io_path(path / "LICENSE").is_file():
            raise ValueError("Bundled rule pack LICENSE is missing")
        files = sorted(io_root.rglob("*.yml")) + sorted(io_root.rglob("*.yaml"))
        if not files or len(files) > 10000:
            raise ValueError("Rule pack has no rules or exceeds the file limit")
        digest = hashlib.sha256()
        definitions = {}
        for file in files:
            # Captured overlays can exceed MAX_PATH under Windows app state
            # redirection. Keep logical names for identity, native paths for IO.
            native = native_io_path(file)
            if native.is_symlink() or native.stat().st_size > 1_000_000:
                raise ValueError("Rule file is a symlink or too large")
            content = native.read_bytes()
            # References in metadata are attribution, not executable remote
            # configs. Only local YAML is passed to the engine.
            data = yaml.load(content, Loader=_SAFE_LOADER)
            if not isinstance(data,dict) or not isinstance(data.get('rules'),list) or not data['rules']:
                raise ValueError(f'Rule pack has no valid rules: {file.name}')
            for rule in data['rules']:
                validate_rule(rule,descriptor,first_party=require_first_party_metadata)
                rule = execution_rule(rule, file.relative_to(io_root).as_posix(), descriptor)
                if rule['id'] in definitions:
                    raise ValueError('Duplicate rule id')
                definitions[rule['id']]=(rule,file.relative_to(io_root).as_posix())
            digest.update(file.relative_to(io_root).as_posix().encode())
            digest.update(content)
        catalog = load_catalog(path, descriptor, definitions, first_party=require_first_party_metadata)
        if native_io_path(path / 'catalog.json').is_file():
            digest.update(b'catalog.json')
            digest.update(native_io_path(path / 'catalog.json').read_bytes())
        program = load_program(path, catalog) if descriptor.bundled and require_first_party_metadata else None
        if program is not None:
            digest.update(b'capabilities.json')
            digest.update(native_io_path(path / 'capabilities.json').read_bytes())
        return ResolvedRulePack(descriptor, path, digest.hexdigest(), catalog, program)
