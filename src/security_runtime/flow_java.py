"""Bounded Java 8 AST call resolution; reflection/ambiguous overloads stay unknown."""
import ast
import copy
import re
from pathlib import Path

import javalang
from javalang import tree as jt

from .flow_core import UNKNOWN, Analysis, Limit, Value, binary, constant, join, truth

SDK = {
    'javax.servlet.http.HttpServletRequest': 'request', 'jakarta.servlet.http.HttpServletRequest': 'request',
    'javax.servlet.http.Cookie': 'cookie', 'jakarta.servlet.http.Cookie': 'cookie',
    'java.sql.Connection': 'connection', 'java.sql.Statement': 'statement',
    'org.springframework.jdbc.core.JdbcTemplate': 'jdbc',
    'org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate': 'jdbc',
    'java.lang.ProcessBuilder': 'builder', 'java.lang.StringBuilder': 'string-builder',
    'java.lang.StringBuffer': 'string-builder', 'java.lang.Runtime': 'runtime-type',
    'java.lang.String': 'string-type', 'java.net.URLDecoder': 'decoder',
    'org.apache.commons.codec.binary.Base64': 'base64-codec',
    'org.springframework.beans.factory.annotation.Autowired': 'injection',
    'javax.inject.Inject': 'injection', 'jakarta.inject.Inject': 'injection',
    **{f'java.io.{n}': 'file-io' for n in ('FileInputStream', 'FileReader', 'FileOutputStream', 'FileWriter', 'RandomAccessFile')},
    'java.io.File': 'path', 'java.nio.file.Path': 'path',
    **{f'java.util.{n}': 'sequence' for n in ('ArrayList', 'LinkedList', 'Vector')},
    **{f'java.util.{n}': 'mapping' for n in ('HashMap', 'Properties')},
    'org.springframework.web.bind.annotation.RestController': 'web-controller',
    'org.springframework.stereotype.Controller': 'web-controller',
    **{f'org.springframework.web.bind.annotation.{n}': 'web-route' for n in
       ('RequestMapping', 'GetMapping', 'PostMapping', 'PutMapping', 'DeleteMapping', 'PatchMapping')},
}


def type_name(node):
    names = []
    while node is not None:
        names.append(node.name)
        node = getattr(node, 'sub_type', None)
    return '.'.join(names)


class JavaFlow:
    def __init__(self, analysis: Analysis):
        self.a = analysis
        self.units, self.classes, self.file_units = {}, {}, {}
        self.roots = {'', 'src/main/java', 'src/test/java'}
        self.file, self.cls, self.line = '', '', 1
        self.field_stack = set()
        self.class_cache = {}
        self.break_frames = []

    def load(self, file):
        if file in self.file_units: return self.file_units[file]
        try:
            unit = javalang.parse.parse(self.a.read(file))
        except (javalang.parser.JavaSyntaxError, javalang.tokenizer.LexerError, UnicodeError, RecursionError):
            self.a.gaps.add((file, 'JAVA8_PARSE_UNSUPPORTED'))
            self.file_units[file] = None
            return None
        package = unit.package.name if unit.package else ''
        parent = Path(file).parent.as_posix()
        suffix = package.replace('.', '/')
        if suffix and parent.endswith(suffix): self.roots.add(parent[:-len(suffix)].rstrip('/'))
        self.file_units[file] = unit
        def register(node, prefix):
            name = prefix + node.name
            self.classes[name] = (file, node)
            for member in node.body:
                if isinstance(member, jt.ClassDeclaration): register(member, name + '.')
        for node in unit.types:
            if isinstance(node, jt.ClassDeclaration): register(node, package + '.' if package else '')
        return unit

    def find_class(self, name):
        # Cache resolution, never function results or mutable field values.
        # New units/source roots invalidate prior misses within this analysis.
        key = (self.file, self.cls, name, len(self.classes), tuple(sorted(self.roots)))
        if key not in self.class_cache: self.class_cache[key] = self.resolve_class(name)
        return self.class_cache[key]

    def resolve_class(self, name):
        if name in self.classes: return name
        unit = self.file_units.get(self.file)
        candidates = [name]
        if '.' not in name and unit:
            if self.cls: candidates.append(self.cls + '.' + name)
            if unit.package: candidates.append(unit.package.name + '.' + name)
            candidates += [i.path + '.' + name if i.wildcard else i.path for i in unit.imports
                           if not i.static and (i.wildcard or i.path.rsplit('.', 1)[-1] == name)]
        for candidate in dict.fromkeys(candidates):
            if candidate in self.classes: return candidate
            relative = candidate.replace('.', '/') + '.java'
            for root in sorted(self.roots):
                file = (Path(root) / relative).as_posix()
                if (self.a.root / file).is_file():
                    self.load(file)
                    if candidate in self.classes: return candidate
        return None

    def typed(self, name):
        resolved = self.find_class(name)
        if resolved: return Value(kind='object', ref=resolved, data={})
        return Value(kind=self.sdk(name))

    def sdk(self, name):
        if name in SDK: return SDK[name]
        if '.' in name: return ''
        unit = self.file_units.get(self.file)
        exact = [i.path for i in unit.imports if not i.static and not i.wildcard and i.path.rsplit('.', 1)[-1] == name] if unit else []
        if exact: return SDK.get(exact[0], '') if len(exact) == 1 else ''
        candidates = [i.path + '.' + name for i in unit.imports if i.wildcard and not i.static] if unit else []
        candidates.append('java.lang.' + name)
        matches = [SDK[c] for c in candidates if c in SDK]
        return matches[0] if len(matches) == 1 else ''

    def fields(self, cls):
        if cls in self.field_stack: return {}
        self.field_stack.add(cls)
        file, node = self.classes[cls]
        old_file, old_cls = self.file, self.cls
        self.file, self.cls = file, cls
        env = {}
        try:
            for field in node.fields:
                for declarator in field.declarators:
                    value = self.expression(declarator.initializer, env) if declarator.initializer else Value()
                    if not value.kind:
                        typed = self.typed(type_name(field.type))
                        injected = any(self.sdk(a.name) == 'injection' and not self.find_class(a.name) for a in field.annotations)
                        if typed.kind == 'object' and injected and value.data is UNKNOWN and not value.taint:
                            value = typed
                        else: value.kind = typed.kind
                    env[declarator.name] = value
        finally:
            self.file, self.cls = old_file, old_cls
            self.field_stack.remove(cls)
        return env

    def resolve(self, qualifier, env):
        if not qualifier: return env.get('this', Value(kind='object', ref=self.cls, data=env))
        if qualifier in env: return env[qualifier]
        full = self.find_class(qualifier)
        if full: return Value(kind='class', ref=full)
        parts = qualifier.split('.')
        for split in range(len(parts) - 1, 0, -1):
            base = '.'.join(parts[:split])
            obj = env.get(base)
            cls = None if obj is not None else self.find_class(base)
            if obj is None and cls: obj = Value(kind='class', ref=cls)
            if obj is not None:
                for member in parts[split:]: obj = self.member(obj, member)
                return obj
        return Value(kind='sdk', ref=qualifier) if self.sdk(qualifier) else Value()

    def member(self, obj, name):
        if obj.kind in {'class', 'object'} and obj.ref in self.classes:
            fields = obj.data if isinstance(obj.data, dict) and name in obj.data else self.fields(obj.ref)
            return fields.get(name, Value())
        return Value()

    def invoke(self, obj, method, args, line):
        if obj.ref not in self.classes or self.a.depth >= self.a.max_depth: return Value()
        file, cls = self.classes[obj.ref]
        methods = [m for m in cls.methods if m.name == method and len(m.parameters) == len(args)]
        if len(methods) != 1:
            self.a.gaps.add((self.file, 'CALL_UNRESOLVED_OR_OVERLOADED'))
            return Value()
        method = methods[0]
        return self.execute(obj, method, args, line)

    def construct(self, obj, args, line):
        _, cls = self.classes[obj.ref]
        methods = [m for m in cls.constructors if len(m.parameters) == len(args)]
        if len(methods) == 1: self.execute(obj, methods[0], args, line)
        elif args or methods: self.a.gaps.add((self.file, 'CONSTRUCTOR_UNRESOLVED_OR_OVERLOADED'))

    def execute(self, obj, method, args, line):
        if self.a.depth >= self.a.max_depth: return Value()
        file, _ = self.classes[obj.ref]
        old_file, old_cls = self.file, self.cls
        self.a.calls.append((old_file, line))
        self.file, self.cls = file, obj.ref
        env = self.fields(obj.ref)
        if isinstance(obj.data, dict): env.update(obj.data)
        env['this'] = obj
        for param, value in zip(method.parameters, args): env[param.name] = value
        self.a.depth += 1
        old_breaks, self.break_frames = self.break_frames, []
        try:
            values, _ = self.block(method.body or [], env)
            value = join(*values)
            if value.data is UNKNOWN and not value.kind and not value.taint:
                declared = getattr(method, 'return_type', None)
                if declared is not None:
                    kind = self.sdk(type_name(declared)) if not self.find_class(type_name(declared)) else ''
                    if kind in {'connection', 'statement', 'jdbc'}: value.kind = kind
            return self.a.through(value, old_file, line, callee=(file, method.position.line))
        finally:
            self.break_frames = old_breaks
            self.a.depth -= 1
            self.file, self.cls = old_file, old_cls
            self.a.calls.pop()

    def call(self, obj, method, args, line):
        if obj.kind in {'class', 'object'}: return self.invoke(obj, method, args, line)
        if obj.kind == 'request':
            value = self.a.source(self.file, line)
            if method == 'getCookies': return Value([Value(taint=value.taint, kind='cookie')], kind='sequence')
            if method in {'getHeader', 'getParameter', 'getQueryString', 'getRequestURI'}: return value
            if method == 'getParameterValues': return Value(taint=value.taint, kind='input-sequence')
            if method in {'getParameterNames', 'getHeaderNames', 'getHeaders'}: return Value(taint=value.taint, kind='input-iterator')
            if method == 'getParameterMap': return Value(taint=value.taint, kind='request-map')
        if obj.kind == 'request-map' and method == 'get': return Value(taint=obj.taint, kind='input-sequence')
        if obj.kind == 'cookie' and method in {'getValue', 'getName'}: return Value(taint=obj.taint)
        if obj.kind == 'connection':
            if method == 'createStatement': return Value(kind='statement')
            if method in {'prepareCall', 'prepareStatement'} and args:
                self.a.emit(self.file, line, 'sql-injection', args[0])
                return Value(kind='prepared-statement')
        sql_methods = {'statement': {'execute', 'executeQuery', 'executeUpdate', 'executeLargeUpdate'},
            'jdbc': {'execute', 'query', 'queryForObject', 'queryForList', 'queryForMap', 'queryForRowSet', 'queryForInt', 'queryForLong', 'update', 'batchUpdate'}}
        if method in sql_methods.get(obj.kind, ()) and args:
            self.a.emit(self.file, line, 'sql-injection', args[0])
        if obj.kind == 'builder':
            if method == 'command': obj.data = args[0].data if len(args) == 1 and isinstance(args[0].data, list) else args
            if method == 'start' and isinstance(obj.data, list): self.command(obj.data, line)
        if obj.kind == 'string-builder' and method == 'append' and args:
            merged = binary('+', obj, args[0])
            obj.data, obj.taint = merged.data, merged.taint
            return obj
        if obj.kind == 'sequence' and isinstance(obj.data, list):
            if method == 'add' and args and len(obj.data) < 32: obj.data.append(args[-1])
            if method == 'remove' and args and isinstance(args[0].data, int) and 0 <= args[0].data < len(obj.data): return obj.data.pop(args[0].data)
            if method == 'get' and args and isinstance(args[0].data, int) and 0 <= args[0].data < len(obj.data): return obj.data[args[0].data]
        if obj.kind == 'mapping' and isinstance(obj.data, dict) and args:
            key = args[0].data
            if isinstance(key, (str, int)):
                if method in {'put', 'setProperty'} and len(args) >= 2: obj.data[key] = args[1]
                if method in {'get', 'getProperty'}: return obj.data.get(key, Value())
        if method in {'toLowerCase', 'toUpperCase', 'trim', 'toString', 'getBytes', 'nextElement'} and obj.kind not in {'sdk', 'class', 'object'}:
            data = obj.data if isinstance(obj.data, str) else UNKNOWN
            if isinstance(data, str):
                if method == 'toLowerCase': data = data.lower()
                elif method == 'toUpperCase': data = data.upper()
                elif method == 'trim': data = data.strip()
                elif method == 'getBytes': data = UNKNOWN
            return Value(taint=obj.taint, data=data)
        if method == 'charAt' and isinstance(obj.data, str) and args and isinstance(args[0].data, int):
            index = args[0].data
            return constant(obj.data[index]) if 0 <= index < len(obj.data) else Value()
        if method in {'equals', 'equalsIgnoreCase', 'contains'} and isinstance(obj.data, str) and args and isinstance(args[0].data, str):
            return constant(args[0].data in obj.data if method == 'contains' else obj.data.lower() == args[0].data.lower() if method == 'equalsIgnoreCase' else obj.data == args[0].data)
        if obj.kind == 'sdk':
            name = str(obj.ref)
            if self.sdk(name) == 'base64-codec' and args:
                if method in {'encodeBase64', 'encodeBase64String'}:
                    # Encoding alone is not a decoded SQL payload. Keep the
                    # original only for a later resolved decoding operation.
                    return Value(kind='encoded-base64', ref=args[0])
                if method == 'decodeBase64':
                    original = args[0].ref if args[0].kind == 'encoded-base64' and isinstance(args[0].ref, Value) else args[0]
                    return Value(taint=original.taint, kind='byte-array')
            if name in {'java.net.URLDecoder', 'URLDecoder', 'String', 'java.lang.String'} and method in {'decode', 'valueOf'}:
                return join(*args)
            if name in {'java.lang.Runtime', 'Runtime'} and method == 'getRuntime': return Value(kind='runtime')
        if obj.kind == 'runtime' and method == 'exec' and args:
            self.a.emit(self.file, line, 'command-injection', args[0])
        return Value()

    def command(self, args, line):
        if not args: return
        first = args[0]
        self.a.emit(self.file, line, 'command-injection', first)
        if isinstance(first.data, str) and first.data.rsplit('/', 1)[-1].lower() in {'sh', 'bash', 'cmd', 'cmd.exe', 'powershell', 'powershell.exe'}:
            for index, value in enumerate(args[:-1]):
                if value.data in {'-c', '/c', '-Command'}: self.a.emit(self.file, line, 'command-injection', args[index + 1])

    def expression(self, node, env):
        self.a.tick()
        if node is None: return Value()
        if getattr(node, 'position', None): self.line = node.position.line
        line = self.line
        if isinstance(node, jt.Literal):
            try:
                text = node.value
                if re.fullmatch(r'\d+[lLfFdD]', text): text = text[:-1]
                value = constant(True if text == 'true' else False if text == 'false' else None if text == 'null' else ast.literal_eval(text))
            except (ValueError, SyntaxError): value = Value()
        elif isinstance(node, jt.MemberReference):
            value = env.get(node.member, Value()) if not node.qualifier else self.member(self.resolve(node.qualifier, env), node.member)
        elif isinstance(node, jt.MethodInvocation):
            obj = self.resolve(node.qualifier, env)
            value = self.call(obj, node.member, [self.expression(a, env) for a in node.arguments], line)
        elif isinstance(node, jt.ClassCreator):
            args = [self.expression(n, env) for n in node.arguments]
            name = type_name(node.type)
            base = name.rsplit('.', 1)[-1]
            cls = self.find_class(name)
            if cls:
                value = Value(self.fields(cls), kind='object', ref=cls)
                self.construct(value, args, line)
            elif self.sdk(name) == 'sequence': value = Value([], kind='sequence')
            elif self.sdk(name) == 'mapping': value = Value({}, kind='mapping')
            elif self.sdk(name) == 'file-io':
                if args: self.a.emit(self.file, line, 'path-traversal', args[0])
                value = Value()
            elif self.sdk(name) == 'path':
                mixed = join(*args); value = Value(mixed.data, mixed.taint, 'path')
            elif self.sdk(name) == 'builder': value = Value(args[0].data if len(args) == 1 and isinstance(args[0].data, list) else args, kind='builder')
            elif self.sdk(name) == 'string-builder':
                mixed = args[0] if args and isinstance(args[0].data, str) else constant('') if not args else Value(taint=join(*args).taint)
                value = Value(mixed.data, mixed.taint, 'string-builder')
            elif self.sdk(name) == 'string-type' and args:
                first = args[0]
                value = Value(first.data, first.taint, first.kind if first.kind == 'encoded-base64' else '', first.ref if first.kind == 'encoded-base64' else None)
            else: value = self.typed(name)
        elif isinstance(node, jt.BinaryOperation):
            left, right = self.expression(node.operandl, env), self.expression(node.operandr, env)
            # Integral division/overflow and shifts need Java-width types; remain unknown.
            if node.operator in {'/', '%', '<<', '>>', '>>>'}:
                value = Value(taint=join(left, right).taint)
            else:
                value = binary({'&&': 'and', '||': 'or'}.get(node.operator, node.operator), left, right)
                if type(value.data) is int and not -(2**31) <= value.data < 2**31: value = Value(taint=value.taint)
        elif isinstance(node, jt.TernaryExpression):
            condition = truth(self.expression(node.condition, env))
            value = self.expression(node.if_true if condition else node.if_false, env) if condition is not None else join(self.expression(node.if_true, copy.deepcopy(env)), self.expression(node.if_false, copy.deepcopy(env)))
        elif isinstance(node, jt.Cast): value = self.expression(node.expression, env)
        elif isinstance(node, jt.ArrayCreator): value = self.expression(node.initializer, env)
        elif isinstance(node, jt.ArrayInitializer): value = Value([self.expression(v, env) for v in node.initializers], kind='sequence')
        elif isinstance(node, jt.Assignment):
            value = self.expression(node.value, env)
            target = node.expressionl
            if isinstance(target, jt.MemberReference):
                if not target.qualifier: env[target.member] = value
                else:
                    obj = self.resolve(target.qualifier, env)
                    if obj.kind == 'object' and isinstance(obj.data, dict): obj.data[target.member] = value
            elif isinstance(target, jt.This) and len(target.selectors or []) == 1 and isinstance(target.selectors[0], jt.MemberReference):
                obj = env.get('this', Value())
                if obj.kind == 'object' and isinstance(obj.data, dict): obj.data[target.selectors[0].member] = value
        elif isinstance(node, jt.This): value = env.get('this', Value())
        else: return Value()
        for selector in getattr(node, 'selectors', None) or []:
            if isinstance(selector, jt.MethodInvocation): value = self.call(value, selector.member, [self.expression(a, env) for a in selector.arguments], selector.position.line if selector.position else line)
            elif isinstance(selector, jt.MemberReference): value = self.member(value, selector.member)
            elif isinstance(selector, jt.ArraySelector):
                index = self.expression(selector.index, env).data
                value = (value.data[index] if isinstance(value.data, list) and isinstance(index, int) and 0 <= index < len(value.data)
                         else Value(taint=value.taint) if value.kind == 'input-sequence' else Value())
        for op in getattr(node, 'prefix_operators', None) or []:
            if op == '!' and truth(value) is not None: value = constant(not truth(value))
            if op == '-' and isinstance(value.data, (int, float)): value = constant(-value.data)
        return value

    def block(self, nodes, env):
        returned = []
        if nodes is None: return returned, False
        if not isinstance(nodes, list): nodes = [nodes]
        for node in nodes:
            self.a.tick()
            if getattr(node, 'position', None): self.line = node.position.line
            if isinstance(node, jt.ReturnStatement): return [*returned, self.expression(node.expression, env)], True
            if isinstance(node, jt.ThrowStatement): return returned, True
            if isinstance(node, jt.BreakStatement):
                if node.goto:
                    self.a.gaps.add((self.file, 'LABELLED_BREAK_UNRESOLVED'))
                    return returned, 'BREAK'
                if self.break_frames and self.break_frames[-1] is not None: self.break_frames[-1].append(copy.deepcopy(env))
                return returned, 'BREAK'
            if isinstance(node, (jt.LocalVariableDeclaration, jt.VariableDeclaration)):
                for item in node.declarators:
                    value = self.expression(item.initializer, env)
                    if not value.kind and value.data is UNKNOWN and not value.taint: value = self.typed(type_name(node.type))
                    env[item.name] = value
            elif isinstance(node, jt.StatementExpression): self.expression(node.expression, env)
            elif isinstance(node, jt.BlockStatement):
                values, stop = self.block(node.statements, env); returned.extend(values)
                if stop: return returned, stop
            elif isinstance(node, jt.IfStatement):
                condition = truth(self.expression(node.condition, env))
                if condition is not None:
                    values, stop = self.block(node.then_statement if condition else node.else_statement, env)
                    returned.extend(values)
                    if stop: return returned, stop
                else:
                    branches = [copy.deepcopy(env), copy.deepcopy(env)]
                    outcomes = [self.block(body, branch) for body, branch in zip((node.then_statement, node.else_statement), branches)]
                    for values, _ in outcomes: returned.extend(values)
                    active = [branch for branch, (_, stop) in zip(branches, outcomes) if not stop]
                    if not active: return returned, True
                    for key in set().union(*(b.keys() for b in active)): env[key] = join(*(b.get(key, Value()) for b in active))
            elif isinstance(node, jt.TryStatement):
                values, stop = self.block(node.block, env); returned.extend(values)
                for catch in node.catches or []:
                    values, _ = self.block(catch.block, copy.deepcopy(env)); returned.extend(values)
                self.block(node.finally_block, env)
                if stop: return returned, True
            elif isinstance(node, jt.ForStatement) and isinstance(node.control, jt.EnhancedForControl):
                sequence = self.expression(node.control.iterable, env)
                if isinstance(sequence.data, list) and len(sequence.data) <= 8:
                    exits = []
                    self.break_frames.append(exits)
                    try:
                        for value in sequence.data:
                            env[node.control.var.declarators[0].name] = value
                            values, stop = self.block(node.body, env)
                            returned.extend(values)
                            if stop: break
                    finally: self.break_frames.pop()
                    if exits:
                        branches = [env, *exits]
                        merged = {key:join(*(b.get(key, Value()) for b in branches)) for key in set().union(*(b.keys() for b in branches))}
                        env.update(merged)
                    elif sequence.data and stop is True: return returned, True
            elif isinstance(node, jt.WhileStatement) and isinstance(node.condition, jt.MethodInvocation):
                condition = node.condition
                sequence = self.resolve(condition.qualifier, env)
                if condition.member == 'hasMoreElements' and sequence.kind == 'input-iterator':
                    # Zero or one abstract iteration, including any break exit.
                    # Later iterations are not a whole-loop or absence proof.
                    before, branch, exits = copy.deepcopy(env), copy.deepcopy(env), []
                    self.break_frames.append(exits)
                    try:
                        values, _ = self.block(node.body, branch)
                        returned.extend(values)
                    finally: self.break_frames.pop()
                    branches = [before, branch, *exits]
                    env.update({key:join(*(b.get(key, Value()) for b in branches)) for key in set().union(*(b.keys() for b in branches))})
                    self.a.gaps.add((self.file, 'REQUEST_ENUMERATION_ONE_PASS'))
                else: self.a.gaps.add((self.file, 'LOOP_UNRESOLVED'))
            elif isinstance(node, jt.SwitchStatement):
                selector = self.expression(node.expression, env).data
                if selector is not UNKNOWN:
                    start = next((i for i, c in enumerate(node.cases) if any(self.expression(label, env).data == selector for label in c.case)), None)
                    if start is None: start = next((i for i, c in enumerate(node.cases) if not c.case), len(node.cases))
                    self.break_frames.append(None)
                    try:
                        for case in node.cases[start:]:
                            values, stop = self.block(case.statements, env); returned.extend(values)
                            if stop == 'BREAK': break
                            if stop: return returned, stop
                    finally: self.break_frames.pop()
                else: self.a.gaps.add((self.file, 'SWITCH_UNRESOLVED'))
        return returned, False

    def analyze(self, file):
        if self.load(file) is None: raise Limit('JAVA8_PARSE_UNSUPPORTED')
        self.file = file
        for cls, (where, node) in list(self.classes.items()):
            if where != file: continue
            self.cls = cls
            for method in node.methods:
                obj = Value(self.fields(cls), kind='object', ref=cls)
                args = [self.typed(type_name(p.type)) for p in method.parameters]
                controller = any(not self.find_class(n.name) and self.sdk(n.name) == 'web-controller' for n in node.annotations)
                route = any(not self.find_class(n.name) and self.sdk(n.name) == 'web-route' for n in method.annotations)
                if controller and route:
                    args = [self.a.source(file, p.position.line if p.position else method.position.line)
                            if v.kind == 'string-type' else v for p, v in zip(method.parameters, args)]
                self.invoke(obj, method.name, args, method.position.line)
