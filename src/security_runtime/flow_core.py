"""Bounded abstract values for source-only analysis; never evaluate target code."""
from dataclasses import dataclass, field
import copy
import hashlib
from pathlib import Path


class _Unknown:
    def __deepcopy__(self, memo):
        return self


UNKNOWN = _Unknown()


@dataclass
class Value:
    data: object = UNKNOWN
    taint: tuple = ()
    kind: str = ''
    ref: object = None
    blocked: frozenset = frozenset()

    def __deepcopy__(self, memo):
        return Value(copy.deepcopy(self.data, memo), self.taint, self.kind, self.ref, self.blocked)


def join(*values):
    values = [v for v in values if isinstance(v, Value)]
    if not values:
        return Value()
    trace = tuple(dict.fromkeys(step for v in values for step in v.taint))[:24]
    first = values[0]
    same = first.data is not UNKNOWN and all(type(v.data) is type(first.data) and v.data == first.data for v in values)
    return Value(first.data if same else UNKNOWN, trace,
                 first.kind if all(v.kind == first.kind for v in values) else '',
                 first.ref if all(v.ref == first.ref for v in values) else None,
                 frozenset.intersection(*(v.blocked for v in values)))


def constant(value):
    return Value(value) if isinstance(value, (str, int, float, bool, type(None))) and len(str(value)) <= 4096 else Value()


def truth(value):
    if value.kind not in {'', 'sequence', 'mapping'}:
        return None
    return bool(value.data) if isinstance(value.data, (str, int, float, bool, type(None), list, dict)) else None


def binary(operator, left, right):
    result = join(left, right)
    a, b = left.data, right.data
    if a is UNKNOWN or b is UNKNOWN or isinstance(a, (dict, list)) or isinstance(b, (dict, list)):
        return Value(taint=result.taint, blocked=result.blocked)
    try:
        if operator == '+': value = str(a) + str(b) if isinstance(a, str) or isinstance(b, str) else a + b
        elif operator == '-': value = a - b
        elif operator == '*':
            if isinstance(a, str) or isinstance(b, str): return Value(taint=result.taint)
            value = a * b
        elif operator == '/': value = a / b
        elif operator == '%': value = a % b
        elif operator == '==': value = a == b
        elif operator == '!=': value = a != b
        elif operator == '>': value = a > b
        elif operator == '>=': value = a >= b
        elif operator == '<': value = a < b
        elif operator == '<=': value = a <= b
        elif operator == 'in': value = a in b
        elif operator == 'not in': value = a not in b
        elif operator == 'and': value = bool(a) and bool(b)
        elif operator == 'or': value = bool(a) or bool(b)
        else: return Value(taint=result.taint)
        return constant(value)
    except (ValueError, TypeError, ArithmeticError, OverflowError):
        return Value(taint=result.taint)


class Limit(Exception):
    pass


@dataclass
class Analysis:
    root: Path
    max_files: int = 256
    max_bytes: int = 8_000_000
    max_steps: int = 1_000_000
    max_depth: int = 6
    hashes: dict = field(default_factory=dict)
    issues: dict = field(default_factory=dict)
    stream_path_issues: set = field(default_factory=set)
    gaps: set = field(default_factory=set)
    steps: int = 0
    depth: int = 0
    total_bytes: int = 0
    calls: list = field(default_factory=list)
    targets: set = field(default_factory=set)

    def tick(self):
        self.steps += 1
        if self.steps > self.max_steps:
            raise Limit('STEP_BUDGET')

    def read(self, name):
        relative = Path(name)
        path = self.root / relative
        if (relative.is_absolute() or '..' in relative.parts or not path.resolve().is_relative_to(self.root) or
                any(p.is_symlink() or p.is_junction() for p in (path, *path.parents) if p != self.root and p.is_relative_to(self.root))):
            raise Limit('UNSAFE_CONTEXT_PATH')
        size = path.stat().st_size
        if name not in self.hashes and (len(self.hashes) >= self.max_files or self.total_bytes + size > self.max_bytes):
            raise Limit('CONTEXT_BUDGET')
        if size > 500_000:
            raise Limit('FILE_BUDGET')
        raw = path.read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        if name in self.hashes and self.hashes[name] != digest:
            raise Limit('SOURCE_CHANGED')
        if name not in self.hashes:
            self.total_bytes += len(raw)
        self.hashes[name] = digest
        return raw.decode('utf-8-sig')

    def source(self, file, line):
        return Value(taint=((file, line, 'SOURCE'),))

    def through(self, value, file, line, *, callee=None):
        if value.taint:
            entry = ((*callee, 'RESOLVED_CALL'),) if callee else ()
            return Value(value.data, (value.taint + entry + ((file, line, 'RESOLVED_CALL'),))[-24:], value.kind, value.ref, value.blocked)
        return value

    def emit(self, file, line, category, value, *, stream_path=False):
        if value.taint and category not in value.blocked and line:
            location = (file, line)
            if self.targets and file not in self.targets:
                location = next((site for site in reversed(self.calls) if site[0] in self.targets), None)
                if location is None:
                    return
            key = (*location, category)
            if stream_path and category == 'path-traversal': self.stream_path_issues.add(key)
            calls = tuple((f, n, 'RESOLVED_CALL') for f, n in self.calls[1:])
            self.issues[key] = tuple(dict.fromkeys((*value.taint, *calls, (file, line, 'SINK'))))[-24:]

    def stable(self):
        try:
            for name, digest in self.hashes.items():
                path = self.root / name
                if (not path.resolve().is_relative_to(self.root) or
                    any(p.is_symlink() or p.is_junction() for p in (path, *path.parents)
                        if p != self.root and p.is_relative_to(self.root)) or
                    hashlib.sha256(path.read_bytes()).hexdigest() != digest):
                    return False
        except OSError:
            return False
        return True
