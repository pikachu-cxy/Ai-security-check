"""Context-sensitive, source-only Python AST interpreter for a bounded API subset."""
import ast
import copy
import re
from pathlib import Path

from .flow_core import UNKNOWN, Analysis, Limit, Value, binary, constant, join, truth


OPS = {ast.Add: '+', ast.Sub: '-', ast.Mult: '*', ast.Div: '/', ast.Mod: '%',
       ast.Eq: '==', ast.NotEq: '!=', ast.Gt: '>', ast.GtE: '>=', ast.Lt: '<', ast.LtE: '<=',
       ast.In: 'in', ast.NotIn: 'not in'}


class PythonFlow:
    def __init__(self, analysis: Analysis):
        self.a = analysis
        self.modules, self.environments = {}, {}
        self.file = ''
        self.current_module = ''
        self.loop_frames = []
        self.dynamic_flask_path = False

    def module(self, name, file=None):
        if name in self.environments:
            return self.environments[name]
        if file is None:
            stem = name.replace('.', '/')
            file = next((p for p in (stem + '.py', stem + '/__init__.py') if self.a.exists(p)), None)
        if file is None:
            return None
        try:
            tree = self.a.parse(file, 'python', lambda text: ast.parse(text, filename=file))
        except (SyntaxError, UnicodeError, RecursionError):
            self.a.gaps.add((file, 'PYTHON_PARSE_UNSUPPORTED'))
            return {}
        self.modules[name] = (file, tree)
        env = self.environments[name] = {}
        old, old_module = self.file, self.current_module
        self.file, self.current_module = file, name
        for node in tree.body:
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                self.statement(node, env)
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                env[node.name] = Value(kind='function', ref=(name, node))
            elif isinstance(node, ast.ClassDef):
                env[node.name] = Value(kind='class', ref=(name, node))
            elif isinstance(node, (ast.Assign, ast.AnnAssign)):
                # Global initializers are interpreted symbolically, never imported/run.
                self.statement(node, env)
        self.file, self.current_module = old, old_module
        return env

    def import_name(self, full):
        if full == 'flask.request':
            if self.module('flask') is None:
                return Value(kind='request')
        parts = full.rsplit('.', 1)
        parent = self.module(parts[0]) if len(parts) == 2 else None
        if parent is not None and len(parts) == 2 and parts[1] in parent:
            return parent[parts[1]]
        return Value(kind='module', ref=full)

    def attribute(self, obj, name):
        if obj.kind == 'module':
            if not isinstance(obj.ref, str): return Value()
            env = self.module(obj.ref)
            if env is not None and name in env:
                return env[name]
            if env is not None and self.module(obj.ref + '.' + name) is None:
                return Value()
            return self.import_name(obj.ref + '.' + name)
        if obj.kind == 'request' and name in {'args', 'form', 'values', 'cookies', 'headers', 'GET', 'POST'}:
            return Value(kind='request-map')
        if obj.kind == 'request' and name in {'data', 'query_string'}:
            value = self.a.source(self.file, self.line)
            return Value(taint=value.taint, kind='bytes')
        if obj.kind == 'request' and name == 'path' and not self.dynamic_flask_path:
            self.a.gaps.add((self.file, 'FLASK_DYNAMIC_PATH_CONTEXT_UNRESOLVED'))
            return Value(kind='str')
        if obj.kind == 'request' and name in {'path', 'full_path', 'url'}:
            return Value(taint=self.a.source(self.file, self.line).taint, kind='str')
        if obj.kind == 'object':
            if isinstance(obj.data, dict) and name in obj.data:
                return obj.data[name]
            if not isinstance(obj.ref, tuple) or len(obj.ref) != 2:
                self.a.gaps.add((self.file, 'AMBIGUOUS_INSTANCE_TYPE'))
                return Value()
            module, cls = obj.ref
            fn = next((n for n in cls.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == name), None)
            if fn is not None:
                return Value(kind='method', ref=(module, fn, obj))
        return Value(kind='bound', ref=(obj, name))

    def call(self, fn, args, kwargs, line):
        if fn.kind in {'function', 'method'}:
            if not isinstance(fn.ref, tuple) or len(fn.ref) not in {2, 3}:
                self.a.gaps.add((self.file, 'AMBIGUOUS_CALL_TARGET'))
                return Value()
            module, node, *bound = fn.ref
            return self.invoke(module, node, ([bound[0]] if bound else []) + args, kwargs, line)
        if fn.kind == 'class':
            if not isinstance(fn.ref, tuple) or len(fn.ref) != 2: return Value()
            module, cls = fn.ref
            obj = Value({}, kind='object', ref=(module, cls))
            init = self.attribute(obj, '__init__')
            if init.kind == 'method': self.call(init, args, kwargs, line)
            return obj
        if fn.kind == 'module':
            name = fn.ref
            value = join(*args)
            if name == 'builtins.input': return self.a.source(self.file, line)
            if name in {'builtins.str', 'urllib.parse.unquote', 'urllib.parse.unquote_plus',
                        'base64.b64decode', 'base64.b64encode', 'os.path.join'}:
                return value
            if name in {'builtins.int', 'builtins.float'}:
                return Value(kind='number')
            if name == 'builtins.len' and len(args) == 1:
                data = args[0].data
                return constant(len(data)) if isinstance(data, (str,list,dict)) else Value(kind='number')
            if name in {'builtins.dict', 'configparser.ConfigParser'}:
                return Value({}, kind='mapping', ref='configparser' if name.startswith('configparser.') else None)
            if name in {'builtins.list', 'builtins.tuple'}:
                return Value(list(args[0].data) if args and isinstance(args[0].data, list) else [], kind='sequence')
            if name in {'pathlib.Path', 'pathlib.PurePath'}:
                return Value(value.data, value.taint, 'path', blocked=value.blocked)
            if name in {'sqlite3.connect', 'psycopg2.connect', 'pymysql.connect'}:
                return Value(kind='connection')
            if name in {'builtins.open', 'io.open', 'codecs.open', 'flask.send_file'} and args:
                self.a.emit(self.file, line, 'path-traversal', args[0], stream_path=name in {'io.open', 'codecs.open'})
                return Value(kind='file')
            if name in {'os.path.exists', 'os.path.isfile', 'os.path.isdir', 'os.stat', 'os.lstat'} and args:
                self.a.emit(self.file, line, 'path-traversal', args[0])
                return Value()
            if name == 'os.system' and args:
                self.a.emit(self.file, line, 'command-injection', args[0])
            if name in {'subprocess.run', 'subprocess.call', 'subprocess.Popen', 'subprocess.check_output'} and args:
                if kwargs.get('shell', Value(False)).data is True:
                    self.a.emit(self.file, line, 'command-injection', args[0])
            if name == 'builtins.getattr':
                return Value()  # Dynamic attribute names are not resolved.
            return Value()
        if fn.kind == 'bound':
            obj, method = fn.ref
            if obj.kind == 'request-map' and method in {'get', 'getlist'}:
                value = self.a.source(self.file, line)
                return Value(taint=value.taint, kind='input-sequence') if method == 'getlist' else Value(taint=value.taint,kind='str')
            if obj.kind == 'request-map' and method == 'keys':
                return Value(taint=self.a.source(self.file,line).taint,kind='input-sequence')
            if obj.kind == 'request' and method in {'get_json', 'get_data'}:
                return self.a.source(self.file, line)
            if obj.kind == 'connection' and method == 'cursor': return Value(kind='cursor')
            if obj.kind == 'cursor' and method in {'execute', 'executemany'} and args:
                self.a.emit(self.file, line, 'sql-injection', args[0])
            if obj.kind == 'mapping' and isinstance(obj.data, dict):
                key = tuple(v.data for v in args[:2]) if obj.ref == 'configparser' and len(args) >= 2 else (args[0].data if args else UNKNOWN)
                if method == 'set' and len(args) == 3 and all(v.data is not UNKNOWN for v in args[:2]): obj.data[key] = args[2]
                if method == 'get': return obj.data.get(key, args[1] if len(args) > 1 and obj.ref != 'configparser' else Value())
            if obj.kind == 'sequence' and isinstance(obj.data, list) and method == 'append' and len(obj.data) < 32 and args: obj.data.append(args[0])
            if obj.kind == 'sequence' and isinstance(obj.data, list) and method == 'pop' and obj.data:
                key = args[0].data if args else -1
                if isinstance(key, int) and -len(obj.data) <= key < len(obj.data): return obj.data.pop(key)
            if obj.kind == 'path' and method in {'read_text', 'read_bytes', 'write_text', 'write_bytes', 'open', 'unlink', 'exists', 'is_file', 'is_dir', 'stat', 'lstat'}:
                self.a.emit(self.file, line, 'path-traversal', obj)
            if obj.kind == 'path' and method in {'resolve', 'absolute', 'expanduser', 'with_name', 'with_suffix', 'joinpath'}:
                value = join(obj, *args)
                return Value(value.data, value.taint, 'path', blocked=value.blocked)
            if method in {'decode', 'encode', 'strip', 'lower', 'upper'} and obj.kind not in {'object', 'module'}:
                kind = 'str' if method == 'decode' else 'bytes' if method == 'encode' else obj.kind
                return Value(taint=obj.taint, kind=kind, blocked=obj.blocked)
            if method in {'find','rfind','index','rindex'} and (obj.kind in {'str','bytes'} or isinstance(obj.data,str)) and args:
                if isinstance(obj.data,str) and isinstance(args[0].data,str):
                    try: return constant(getattr(obj.data,method)(args[0].data))
                    except ValueError: return Value()
                return Value(kind='number')
            if method in {'split', 'rsplit'}:
                if (len(args) > 2 or set(kwargs) - {'sep', 'maxsplit'} or
                        args and 'sep' in kwargs or len(args) > 1 and 'maxsplit' in kwargs):
                    return Value()
                separator = args[0].data if args else kwargs.get('sep', constant(None)).data
                maximum = args[1].data if len(args) > 1 else kwargs.get('maxsplit', constant(-1)).data
                if ((separator is None or isinstance(separator, str) and separator) and
                        type(maximum) is int):
                    if isinstance(obj.data, str):
                        parts = getattr(obj.data, method)(separator, maximum)
                        if len(parts) <= 32: return Value([constant(part) for part in parts], kind='sequence')
                    elif obj.kind == 'str' and obj.taint:
                        return Value(taint=obj.taint, kind='input-sequence')
            if isinstance(obj.data, str) and method in {'startswith', 'endswith'} and args and isinstance(args[0].data, str):
                return constant(obj.data.startswith(args[0].data) if method == 'startswith' else obj.data.endswith(args[0].data))
        return Value()

    def invoke(self, module, node, args, kwargs, line):
        if self.a.depth >= self.a.max_depth:
            self.a.gaps.add((self.file, 'CALL_DEPTH'))
            return Value()
        old, old_module = self.file, self.current_module
        self.a.calls.append((old, line))
        self.file, self.current_module = self.modules[module][0], module
        env = dict(self.environments[module])
        parameters = [*node.args.posonlyargs, *node.args.args]
        defaults = [None] * (len(parameters) - len(node.args.defaults)) + list(node.args.defaults)
        names = {p.arg for p in [*parameters, *node.args.kwonlyargs]}
        if ((len(args) > len(parameters) and node.args.vararg is None) or
            any(p.arg in kwargs for p in parameters[:len(args)]) or
            any(p.arg in kwargs for p in node.args.posonlyargs) or
            (node.args.kwarg is None and bool(set(kwargs) - names)) or
            any(i >= len(args) and p.arg not in kwargs and d is None for i,(p,d) in enumerate(zip(parameters, defaults))) or
            any(p.arg not in kwargs and d is None for p,d in zip(node.args.kwonlyargs, node.args.kw_defaults))):
            self.file, self.current_module = old, old_module
            self.a.calls.pop()
            self.a.gaps.add((old, 'ARGUMENT_BINDING_UNRESOLVED'))
            return Value()
        for index, (param, default) in enumerate(zip(parameters, defaults)):
            env[param.arg] = args[index] if index < len(args) else kwargs.get(param.arg,
                constant(default.value) if isinstance(default, ast.Constant) else Value())
        for param, default in zip(node.args.kwonlyargs, node.args.kw_defaults):
            env[param.arg] = kwargs.get(param.arg, constant(default.value) if isinstance(default, ast.Constant) else Value())
        if node.args.vararg: env[node.args.vararg.arg] = Value(args[len(parameters):], kind='sequence')
        if node.args.kwarg:
            env[node.args.kwarg.arg] = Value({k:v for k,v in kwargs.items() if k not in names}, kind='mapping')
        self.a.depth += 1
        old_frames,self.loop_frames = self.loop_frames,[]
        old_path_context = self.dynamic_flask_path
        # Static routes have fixed path segments. Carry a declared dynamic-route
        # context through resolved helper calls, and restore it between entries.
        self.dynamic_flask_path = old_path_context or any(
            isinstance(d, ast.Call) and isinstance(d.func, ast.Attribute) and d.func.attr == 'route'
            and d.args and isinstance(d.args[0], ast.Constant) and isinstance(d.args[0].value, str)
            and re.search(r'<(?:[A-Za-z_][\w]*(?:\([^<>]*\))?:)?[A-Za-z_][\w]*>', d.args[0].value)
            for d in node.decorator_list)
        try:
            returned, _ = self.block(node.body, env)
            return self.a.through(join(*returned), old, line, callee=(self.file, node.lineno))
        finally:
            self.loop_frames = old_frames
            self.dynamic_flask_path = old_path_context
            self.a.depth -= 1
            self.file, self.current_module = old, old_module
            self.a.calls.pop()

    def expression(self, node, env):
        self.a.tick()
        self.line = getattr(node, 'lineno', 1)
        if node is None: return Value()
        if isinstance(node, ast.Constant): return constant(node.value)
        if isinstance(node, ast.Name): return env[node.id] if node.id in env else self.import_name('builtins.' + node.id)
        if isinstance(node, ast.Attribute): return self.attribute(self.expression(node.value, env), node.attr)
        if isinstance(node, ast.Call):
            if any(isinstance(a, ast.Starred) for a in node.args) or any(k.arg is None for k in node.keywords):
                self.a.gaps.add((self.file, 'DYNAMIC_ARGUMENTS_UNRESOLVED'))
                return Value()
            fn = self.expression(node.func, env)
            return self.call(fn, [self.expression(n, env) for n in node.args],
                             {k.arg: self.expression(k.value, env) for k in node.keywords if k.arg}, node.lineno)
        if isinstance(node, ast.BinOp):
            left, right = self.expression(node.left, env), self.expression(node.right, env)
            if isinstance(node.op, ast.Div) and left.kind == 'path':
                value = join(left, right)
                return Value(taint=value.taint, kind='path', blocked=value.blocked)
            value = binary(OPS.get(type(node.op), ''), left, right)
            if (value.data is UNKNOWN and isinstance(node.op,(ast.Add,ast.Sub,ast.Mult)) and
                all(v.kind == 'number' or type(v.data) in {int,float} for v in (left,right))):
                value.kind = 'number'
            return value
        if isinstance(node, ast.JoinedStr): return join(*(self.expression(n.value if isinstance(n, ast.FormattedValue) else n, env) for n in node.values))
        if isinstance(node, ast.Compare) and len(node.ops) == 1:
            return binary(OPS.get(type(node.ops[0]), ''), self.expression(node.left, env), self.expression(node.comparators[0], env))
        if isinstance(node, ast.BoolOp):
            return join(*(self.expression(n, env) for n in node.values))
        if isinstance(node, ast.UnaryOp):
            value = self.expression(node.operand, env)
            if isinstance(node.op, ast.Not) and truth(value) is not None: return constant(not truth(value))
            if isinstance(node.op, ast.USub) and isinstance(value.data, (int, float)): return constant(-value.data)
            return value
        if isinstance(node, (ast.List, ast.Tuple)): return Value([self.expression(n, env) for n in node.elts], kind='sequence')
        if isinstance(node, ast.Dict):
            data = {}
            for k, v in zip(node.keys, node.values):
                key = self.expression(k, env).data
                if isinstance(key, (str, int)): data[key] = self.expression(v, env)
            return Value(data, kind='mapping')
        if isinstance(node, ast.Subscript):
            obj = self.expression(node.value, env)
            if obj.kind == 'request-map': return self.a.source(self.file, node.lineno)
            if isinstance(node.slice, ast.Slice):
                values = [self.expression(n,env) if n is not None else constant(None) for n in
                          (node.slice.lower,node.slice.upper,node.slice.step)]
                bounds = [v.data for v in values]
                if all(n is None or type(n) is int for n in bounds) and bounds[2] != 0:
                    if isinstance(obj.data, (str, list)):
                        data = obj.data[slice(*bounds)]
                        return Value(data, obj.taint, obj.kind, blocked=obj.blocked)
                    if obj.taint: return Value(taint=obj.taint, blocked=obj.blocked)
                if (obj.kind in {'str','bytes'} and obj.taint and bounds[2] != 0 and
                    all(v.data is None or type(v.data) is int or v.kind == 'number' for v in values)):
                    return Value(taint=obj.taint,kind=obj.kind,blocked=obj.blocked)
                return Value()
            key = self.expression(node.slice, env).data
            if obj.kind == 'input-sequence' and type(key) is int: return Value(taint=obj.taint,kind='str')
            if isinstance(obj.data, dict) and isinstance(key, (str, int)): return obj.data.get(key, Value())
            if isinstance(obj.data, (str, list)) and isinstance(key, int) and -len(obj.data) <= key < len(obj.data):
                value = obj.data[key]
                return value if isinstance(value, Value) else constant(value)
            return Value()
        if isinstance(node, ast.IfExp):
            condition = truth(self.expression(node.test, env))
            if condition is not None: return self.expression(node.body if condition else node.orelse, env)
            return join(self.expression(node.body, copy.deepcopy(env)), self.expression(node.orelse, copy.deepcopy(env)))
        return Value()

    def assign(self, target, value, env):
        if isinstance(target, ast.Name): env[target.id] = value
        elif isinstance(target, ast.Attribute):
            obj = self.expression(target.value, env)
            if obj.kind == 'object' and isinstance(obj.data, dict): obj.data[target.attr] = value
        elif isinstance(target, ast.Subscript):
            obj, key = self.expression(target.value, env), self.expression(target.slice, env).data
            if isinstance(obj.data, dict) and isinstance(key, (str, int)): obj.data[key] = value

    def statement(self, node, env):
        self.a.tick()
        self.line = getattr(node, 'lineno', 1)
        if isinstance(node, ast.Import):
            for n in node.names: env[n.asname or n.name.split('.')[0]] = self.import_name(n.name if n.asname else n.name.split('.')[0])
        elif isinstance(node, ast.ImportFrom):
            prefix = node.module or ''
            if node.level:
                file = self.modules[self.current_module][0]
                package = self.current_module.removesuffix('.__init__') if file.endswith('/__init__.py') else self.current_module.rpartition('.')[0]
                parts = package.split('.') if package else []
                if node.level > len(parts):
                    self.a.gaps.add((self.file, 'RELATIVE_IMPORT_UNRESOLVED'))
                    return
                prefix = '.'.join(parts[:len(parts)-node.level+1] + ([prefix] if prefix else []))
            for n in node.names:
                if n.name != '*': env[n.asname or n.name] = self.import_name(prefix + '.' + n.name)
        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
            value = self.expression(node.value, env)
            for target in (node.targets if isinstance(node, ast.Assign) else [node.target]): self.assign(target, value, env)
        elif isinstance(node, ast.AugAssign): self.assign(node.target, binary(OPS.get(type(node.op), ''), self.expression(node.target, env), self.expression(node.value, env)), env)
        elif isinstance(node, ast.Expr): self.expression(node.value, env)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            env[node.name] = Value(kind='function', ref=(self.current_module, node))

    def merge_environment(self, env, branches):
        env.update({key:join(*(b.get(key,Value()) for b in branches)) for key in set().union(*(b.keys() for b in branches))})

    def for_block(self, node, env):
        sequence=self.expression(node.iter,env)
        returned=[]
        frame={'break':[],'continue':[]}
        normal=[]
        self.loop_frames.append(frame)
        try:
            if isinstance(sequence.data,list) and len(sequence.data)<=8:
                normal=[env]
                for value in sequence.data:
                    frame['continue'].clear()
                    self.assign(node.target,value,env)
                    values,stop=self.block(node.body,env);returned.extend(values)
                    normal=[*frame['continue']]+([] if stop else [env])
                    if not normal: break
                    self.merge_environment(env,normal)
                    normal=[env]
            elif sequence.kind=='input-sequence':
                normal=[copy.deepcopy(env)]  # zero iterations remain possible
                branch=copy.deepcopy(env)
                self.assign(node.target,Value(taint=sequence.taint,kind='str'),branch)
                values,stop=self.block(node.body,branch);returned.extend(values)
                if not stop: normal.append(branch)
                normal.extend(frame['continue'])
                self.a.gaps.add((self.file,'REQUEST_ITERABLE_ONE_PASS'))
            else:
                self.a.gaps.add((self.file,'LOOP_UNRESOLVED'))
                return returned,False
        finally: self.loop_frames.pop()
        active=[]
        for branch in normal:
            values,stop=self.block(node.orelse,branch);returned.extend(values)
            if not stop: active.append(branch)
        active.extend(frame['break'])
        if not active: return returned,True
        self.merge_environment(env,active)
        return returned,False

    def block(self, nodes, env):
        returned = []
        for node in nodes:
            if isinstance(node,(ast.Break,ast.Continue)):
                action='break' if isinstance(node,ast.Break) else 'continue'
                if self.loop_frames: self.loop_frames[-1][action].append(copy.deepcopy(env))
                else: self.a.gaps.add((self.file,'LOOP_CONTROL_UNRESOLVED'))
                return returned,action.upper()
            if isinstance(node, ast.Return):
                returned.append(self.expression(node.value, env))
                return returned, True
            if isinstance(node, ast.If):
                condition = truth(self.expression(node.test, env))
                if condition is not None:
                    values, stop = self.block(node.body if condition else node.orelse, env)
                    returned.extend(values)
                    if stop: return returned, stop
                else:
                    branches = [copy.deepcopy(env), copy.deepcopy(env)]
                    outcomes = [self.block(body, branch) for body, branch in zip((node.body, node.orelse), branches)]
                    for values, _ in outcomes: returned.extend(values)
                    active = [branch for branch, (_, stop) in zip(branches, outcomes) if not stop]
                    if not active: return returned, True
                    for key in set().union(*(b.keys() for b in active)): env[key] = join(*(b.get(key, Value()) for b in active))
            elif isinstance(node, (ast.Try, ast.With)):
                if isinstance(node, ast.With):
                    for item in node.items:
                        value = self.expression(item.context_expr, env)
                        if item.optional_vars is not None: self.assign(item.optional_vars, value, env)
                values, stop = self.block(node.body, env)
                returned.extend(values)
                if isinstance(node, ast.Try):
                    for handler in node.handlers:
                        values, _ = self.block(handler.body, copy.deepcopy(env)); returned.extend(values)
                    self.block(node.finalbody, env)
                if stop: return returned, stop
            elif isinstance(node, ast.For):
                values,stop=self.for_block(node,env);returned.extend(values)
                if stop: return returned,stop
            elif isinstance(node, ast.Match):
                subject = self.expression(node.subject,env)
                if subject.data is UNKNOWN:
                    self.a.gaps.add((self.file,'MATCH_UNRESOLVED'))
                    continue
                for case in node.cases:
                    def matches(pattern):
                        if isinstance(pattern,ast.MatchValue) and isinstance(pattern.value,ast.Constant): return subject.data == pattern.value.value
                        if isinstance(pattern,ast.MatchSingleton): return subject.data is pattern.value
                        if isinstance(pattern,ast.MatchOr):
                            outcomes=[matches(p) for p in pattern.patterns]
                            return True if True in outcomes else None if None in outcomes else False
                        if isinstance(pattern,ast.MatchAs) and pattern.pattern is None: return True
                        return None
                    matched=matches(case.pattern)
                    if matched is None:
                        self.a.gaps.add((self.file,'MATCH_PATTERN_UNRESOLVED'));break
                    if not matched: continue
                    guard = truth(self.expression(case.guard,env)) if case.guard else True
                    if guard is None:
                        self.a.gaps.add((self.file,'MATCH_GUARD_UNRESOLVED'));break
                    if not guard: continue
                    if isinstance(case.pattern,ast.MatchAs) and case.pattern.name: env[case.pattern.name]=subject
                    values,stop=self.block(case.body,env);returned.extend(values)
                    if stop: return returned,stop
                    break
            else: self.statement(node, env)
        return returned, False

    def analyze(self, file):
        module = (file.removesuffix('/__init__.py') if file.endswith('/__init__.py') else file.removesuffix('.py')).replace('/', '.')
        self.module(module, file)
        if module not in self.modules: raise Limit('PYTHON_PARSE_UNSUPPORTED')
        self.file, tree = self.modules[module]
        self.current_module = module
        # Nested route functions are entry candidates; no target function is executed.
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name != '__init__':
                # Names such as request/cursor alone do not establish an SDK type.
                args = [Value() for p in [*node.args.posonlyargs, *node.args.args]]
                self.invoke(module, node, args, {p.arg:Value() for p in node.args.kwonlyargs}, node.lineno)
