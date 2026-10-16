"""Rule packs have their own provenance, licensing and lifecycle."""
from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Protocol
from .rule_catalog import RuleRecord, validate_rule, load_catalog
from .rule_program import RuleProgram, load_program

import yaml


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
    def resolve(self, rule_pack_id: str) -> ResolvedRulePack: ...


class RulePackUpdateProvider(RulePackProvider, Protocol):
    """Future signed updates must verify before activation and allow rollback."""

    def stage(self, rule_pack_id: str, version: str, checksum: str, signature: bytes) -> ResolvedRulePack: ...
    def activate(self, candidate: ResolvedRulePack) -> None: ...
    def rollback(self, rule_pack_id: str, version: str) -> None: ...


FIRST_PARTY_RULE_PACK = RulePackDescriptor(
    "ai-security-core", "AI Security Runtime Core Rules", "1.3.2", "AI Security Runtime",
    "Copyright AI Security Runtime contributors", "Apache-2.0", "https://www.apache.org/licenses/LICENSE-2.0",
    True, True, True, True, "bundled local package",
    RuleProvenance("FIRST_PARTY", "AI Security Runtime contributors", "2026-09-29",
                   ("https://cwe.mitre.org/data/definitions/78.html",), "Apache-2.0"),
    True, RulePackClass.FIRST_PARTY)


def can_bundle_rule_pack(descriptor: RulePackDescriptor) -> bool:
    return bool(descriptor.bundled and descriptor.pack_class in {RulePackClass.FIRST_PARTY, RulePackClass.PERMISSIVE_THIRD_PARTY}
                and descriptor.commercial_use_allowed and descriptor.redistribution_allowed and descriptor.hosted_service_allowed)


class BundledRulePackProvider:
    def __init__(self, path: Path | None = None):
        self.path = path or Path(__file__).parent / "rules"

    def discover(self) -> list[ResolvedRulePack]:
        return [self.resolve(FIRST_PARTY_RULE_PACK.rule_pack_id)]

    def resolve(self, rule_pack_id: str) -> ResolvedRulePack:
        if rule_pack_id != FIRST_PARTY_RULE_PACK.rule_pack_id:
            raise KeyError(rule_pack_id)
        return RulePackManager._validate(FIRST_PARTY_RULE_PACK, self.path)


class RulePackManager:
    def __init__(self, provider: RulePackProvider | None = None):
        self.provider = provider or BundledRulePackProvider()
        self._resolved_cache = {}  # Validated metadata only, never scan evidence.
        self._cache_lock = threading.RLock()
        self.cache_hit = False

    @staticmethod
    def _content_identity(path):
        path = path.expanduser().resolve()
        if not path.is_dir():
            raise ValueError('Rule pack directory is missing')
        files = sorted(path.rglob('*.yml')) + sorted(path.rglob('*.yaml'))
        if not files or len(files) > 1000:
            raise ValueError('Rule pack file budget exceeded')
        files += [p for p in (path/'catalog.json',path/'capabilities.json',path/'LICENSE',path/'NOTICE') if p.is_file()]
        digest = hashlib.sha256()
        for file in files:
            if file.is_symlink() or file.is_junction() or file.stat().st_size > 1_000_000:
                raise ValueError('Invalid rule pack input')
            digest.update(file.relative_to(path).as_posix().encode());digest.update(file.read_bytes())
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
            result = self._validate(descriptor,path,**kwargs)
            if self._content_identity(path) != key[2]:
                raise ValueError('Rule pack changed during validation')
            size=sum(p.stat().st_size for p in (*path.rglob('*.yml'),*path.rglob('*.yaml')))
            if len(result.catalog)<=1000 and size<=4_000_000:
                if len(self._resolved_cache) >= 8:
                    self._resolved_cache.pop(next(iter(self._resolved_cache)))
                self._resolved_cache[key] = result
            return result

    def discover(self) -> list[ResolvedRulePack]:
        return self.provider.discover()

    def resolve(self, rule_pack_id: str = "ai-security-core", *, user_path: Path | None = None) -> ResolvedRulePack:
        if user_path is None:
            if type(self.provider) is BundledRulePackProvider:
                if rule_pack_id != FIRST_PARTY_RULE_PACK.rule_pack_id:
                    raise KeyError(rule_pack_id)
                return self._cached_resolve(FIRST_PARTY_RULE_PACK,self.provider.path)
            self.cache_hit = False  # External providers retain their lifecycle.
            return self.provider.resolve(rule_pack_id)
        descriptor = RulePackDescriptor(
            "user-provided", "User provided rules", "unversioned", "User", "User owned", "User provided",
            "", False, False, False, False, str(user_path),
            RuleProvenance("USER_PROVIDED", "User", "", (), "User provided"), False, RulePackClass.USER_PROVIDED)
        # The caller owns these rules. We validate local scope, never copy them.
        return self._cached_resolve(descriptor, user_path, require_first_party_metadata=False)

    @staticmethod
    def _validate(descriptor: RulePackDescriptor, path: Path, *, require_first_party_metadata: bool = True) -> ResolvedRulePack:
        path = path.expanduser().resolve()
        if not path.is_dir():
            raise ValueError("Rule pack directory is missing")
        if descriptor.bundled and not can_bundle_rule_pack(descriptor):
            raise ValueError("Rule pack license blocks bundling")
        if descriptor.bundled and not (path / "LICENSE").is_file():
            raise ValueError("Bundled rule pack LICENSE is missing")
        files = sorted(path.rglob("*.yml")) + sorted(path.rglob("*.yaml"))
        if not files or len(files) > 1000:
            raise ValueError("Rule pack has no rules or exceeds the file limit")
        digest = hashlib.sha256()
        definitions = {}
        for file in files:
            if file.is_symlink() or file.stat().st_size > 1_000_000:
                raise ValueError("Rule file is a symlink or too large")
            content = file.read_bytes()
            if any(marker in content for marker in (b"--config" + b"=auto", b"semgrep" + b".dev/registry", b"semgrep" + b"-rules")):
                raise ValueError("Rule pack references a remote registry")
            data = yaml.safe_load(content)
            if not isinstance(data,dict) or not isinstance(data.get('rules'),list) or not data['rules']:
                raise ValueError(f'Rule pack has no valid rules: {file.name}')
            for rule in data['rules']:
                validate_rule(rule,descriptor,first_party=require_first_party_metadata)
                if rule['id'] in definitions:
                    raise ValueError('Duplicate rule id')
                definitions[rule['id']]=(rule,file.relative_to(path).as_posix())
            digest.update(file.relative_to(path).as_posix().encode())
            digest.update(content)
        catalog = load_catalog(path, descriptor, definitions, first_party=require_first_party_metadata)
        if (path / 'catalog.json').is_file():
            digest.update(b'catalog.json')
            digest.update((path / 'catalog.json').read_bytes())
        program = load_program(path, catalog) if descriptor.bundled and require_first_party_metadata else None
        if program is not None:
            digest.update(b'capabilities.json')
            digest.update((path / 'capabilities.json').read_bytes())
        return ResolvedRulePack(descriptor, path, digest.hexdigest(), catalog, program)
