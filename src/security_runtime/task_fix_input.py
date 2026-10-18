"""Bounded input preparation for originating-provider verification only."""
from dataclasses import dataclass, field
import hashlib
import os
from pathlib import Path

from .models import ScanMode
from .scan_request import ScanRequest, ScanBinding, ScanInputError, SourceKind
from .task_risk_ledger import current_hashes


@dataclass(frozen=True)
class VerificationInput:
    request: ScanRequest
    hashes: dict = field(repr=False)
    rule_pack: object = field(default=None, repr=False)
    rule_manager: object = field(default=None, repr=False)

    def matches(self, view):
        view.assert_intact()
        entries={row.path:row for row in view.manifest if row.role in {'TARGET','CONTEXT','ABSENT'}}
        if set(entries)!=set(self.hashes): return False
        for name,expected in self.hashes.items():
            if expected is None:
                if entries[name].role!='ABSENT': return False
            elif (entries[name].role=='ABSENT' or
                    hashlib.sha256((view.execution_root/name).read_bytes()).hexdigest()!=expected):
                return False
        return True

    def bind_rules(self, view):
        return (self.rule_manager.bind_input(self.rule_pack,view.rules_path)
                if self.rule_pack is not None else None)


def prepare_input(registry,root,members,before):
    from .scanners import PatternSASTScanner
    root=Path(root)
    targets={row['file_path'] for row in members}
    configuration={'.gitleaks.toml','.gitleaksignore','.semgrepignore'}
    for name in ('GITLEAKS_CONFIG','TRIVY_CONFIG'):
        value=os.getenv(name)
        if value:
            path=Path(value).expanduser()
            path=(root/path).resolve() if not path.is_absolute() else path.resolve()
            if path.is_relative_to(root): configuration.add(path.relative_to(root).as_posix())
    hashes=dict(before)
    hashes.update({name:revision for name,revision in current_hashes(root,configuration).items() if name not in hashes})
    origins={name for row in members for name in row.get('scanner_sources',[])}
    bindings=[]
    pack=manager=None
    for adapter in (*registry.adapters,*getattr(registry,'fallback_adapters',())):
        if adapter.name not in origins: continue
        reader=getattr(adapter,'input_bindings',None)
        if callable(reader): bindings.extend(reader())
        if isinstance(adapter,PatternSASTScanner):
            try: selected=adapter.rule_packs.resolve()
            except (OSError,ValueError,KeyError):
                continue  # An unavailable original provider remains a gap.
            if pack is not None and selected!=pack:
                raise ScanInputError('VERIFICATION_RULE_INPUT_MISMATCH')
            pack,manager=selected,adapter.rule_packs
    if pack is not None:
        bindings.append(ScanBinding('RULES',pack.descriptor.rule_pack_id,pack.checksum))
    request=ScanRequest(root,ScanMode.FEATURE,SourceKind.WORKTREE,
        tuple(sorted(name for name in targets if hashes.get(name) is not None)),
        context_files=tuple(sorted(name for name in hashes if name not in targets and hashes[name] is not None)),
        absent_files=tuple(sorted(name for name in hashes if hashes[name] is None)),
        rules_path=pack.path if pack is not None else None,bindings=tuple(bindings))
    return VerificationInput(request,hashes,pack,manager)
