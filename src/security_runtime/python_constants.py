"""Bounded local value and exact literal-guard proofs for built-in injection rules.

Target code is never imported or executed. The models assume standard Python
string and ConfigParser semantics; arbitrary helper/sanitizer names and absence
of taint are not safety proofs. Unsupported values retain the original alert.
"""
import ast
import itertools
import operator
import time
from dataclasses import dataclass, field

UNKNOWN = None
CONFIG_MODULE = object()
STRING_LITERAL = object()


@dataclass
class LocalConfig:
    """Only a freshly constructed, unaliased ConfigParser with explicit values."""
    sections: dict = field(default_factory=dict)


def mutable(value):
    return isinstance(value,(dict,LocalConfig))


def one_string(value):
    if isinstance(value,frozenset) and len(value)==1:
        result=next(iter(value))
        if type(result) is str:return result
    return None
RULES = {'ai-security.python.command-injection', 'ai-security.python.unsafe-eval', 'ai-security.python.sql-injection',
         'ai-security.python.path-traversal', 'ai-security.python.flask-html-response'}
HTML_RULE = 'ai-security.python.flask-html-response'
OPS = {ast.Add:operator.add, ast.Sub:operator.sub, ast.Mult:operator.mul,
       ast.Gt:operator.gt, ast.GtE:operator.ge, ast.Lt:operator.lt, ast.LtE:operator.le,
       ast.Eq:operator.eq, ast.NotEq:operator.ne}


def call_rule(call):
    name=ast.unparse(call.func)
    return ('ai-security.python.unsafe-eval' if name in {'eval','exec'} else
            'ai-security.python.command-injection' if name in {'os.system','subprocess.run','subprocess.call','subprocess.Popen'} else
            'ai-security.python.path-traversal' if name in {'open','flask.send_file'} else
            'ai-security.python.sql-injection' if isinstance(call.func,ast.Attribute) and call.func.attr=='execute' else '')


def choices(*values):
    if not values or any(not isinstance(v,frozenset) for v in values): return UNKNOWN
    result=frozenset().union(*values)
    return result if len(result)<=8 else UNKNOWN


def formatted_html(node):
    """Possible operands of the separate direct Flask string-response rule."""
    return (isinstance(node, ast.JoinedStr) or
            isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)) or
            isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and
            node.func.attr == 'format' and isinstance(node.func.value, ast.Constant) and
            isinstance(node.func.value.value, str))


class Proof:
    def __init__(self,text,seconds=.2):
        if len(text)>250_000: raise ValueError('CONSTANT_FILE_BUDGET')
        self.deadline=time.monotonic()+seconds;self.steps=0;self.safe={};self.bases={}
        self.tree=ast.parse(text)
        nodes=list(ast.walk(self.tree))
        if len(nodes)>20_000: raise ValueError('CONSTANT_NODE_BUDGET')
        for node in nodes:
            if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef)):
                if time.monotonic()>=self.deadline:raise ValueError('CONSTANT_WORK_BUDGET')
                # A deliberately small straight-line/if/match subset. Unsupported
                # writes, repeated execution and closures retain every raw alert.
                body_nodes=list(ast.walk(node))
                unsupported=(ast.Global,ast.Nonlocal,ast.NamedExpr,ast.For,ast.AsyncFor,
                    ast.While,ast.With,ast.AsyncWith,ast.Lambda,ast.ListComp,
                    ast.SetComp,ast.DictComp,ast.GeneratorExp,ast.Await,ast.Yield,ast.YieldFrom)
                if any(isinstance(n,unsupported) for n in body_nodes): continue
                if any(isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef)) and n is not node for n in body_nodes): continue
                if any(isinstance(n,ast.Assign) and (len(n.targets)!=1 or any(not isinstance(t,(ast.Name,ast.Subscript)) for t in n.targets)) for n in body_nodes): continue
                # Global imports can be rebound by other functions. Only an
                # import in this function establishes a supported parser binding.
                env={}
                self.html_context = any(isinstance(d, ast.Call) and isinstance(d.func, ast.Attribute)
                                        and d.func.attr == 'route' for d in node.decorator_list)
                for arg in (*node.args.posonlyargs,*node.args.args,*node.args.kwonlyargs,node.args.vararg,node.args.kwarg):
                    if arg:env[arg.arg]=UNKNOWN
                self.block(node.body,env)
        # Top-level source is not analysed: local function bindings are isolated
        # from changes to globals by arbitrary calls.

    def tick(self):
        self.steps+=1
        if self.steps>30_000 or self.steps%128==1 and time.monotonic()>=self.deadline:
            raise ValueError('CONSTANT_WORK_BUDGET')

    def value(self,node,env):
        self.tick()
        if isinstance(node,ast.Constant) and type(node.value) in {str,int,bool,float}:
            if len(str(node.value))<=4096:return frozenset([node.value])
        if isinstance(node,ast.Name):return env.get(node.id)
        if isinstance(node,ast.Call) and isinstance(node.func,ast.Attribute) and isinstance(node.func.value,ast.Name):
            obj=env.get(node.func.value.id)
            if obj is CONFIG_MODULE and node.func.attr=='ConfigParser' and not node.args and not node.keywords:
                return LocalConfig()
            if isinstance(obj,LocalConfig) and node.func.attr=='get' and len(node.args)==2 and not node.keywords:
                section,key=(one_string(self.value(arg,env)) for arg in node.args)
                if section is not None and key is not None:
                    value=obj.sections.get(section,{}).get(key.lower())
                    # Interpolation can reach another (possibly dynamic) key.
                    if isinstance(value,frozenset) and all(type(v) is str and '%' not in v for v in value):return value
                return UNKNOWN
            if isinstance(obj,dict) and node.func.attr=='get' and len(node.args) in {1,2} and not node.keywords:
                key=self.value(node.args[0],env)
                default=self.value(node.args[1],env) if len(node.args)==2 else UNKNOWN
                if isinstance(key,frozenset):return choices(*(obj.get(k,default) for k in key))
        if isinstance(node,ast.Dict):
            result={}
            for k,v in zip(node.keys,node.values):
                key=self.value(k,env)
                if not isinstance(key,frozenset) or len(key)!=1:return UNKNOWN
                value=self.value(v,env)
                if mutable(value):return UNKNOWN
                result[next(iter(key))]=value
            return result
        if isinstance(node,ast.Subscript):
            obj,key=self.value(node.value,env),self.value(node.slice,env)
            if isinstance(key,frozenset):
                if isinstance(obj,dict):return choices(*(obj.get(k) for k in key))
                if isinstance(obj,frozenset):
                    try:return choices(*(frozenset([v[k]]) for v,k in itertools.product(obj,key)))
                    except (TypeError,IndexError,KeyError):pass
        if isinstance(node,ast.BinOp) and type(node.op) in OPS:
            left,right=self.value(node.left,env),self.value(node.right,env)
            if isinstance(left,frozenset) and isinstance(right,frozenset):
                results=[]
                for a,b in itertools.product(left,right):
                    # Bound before multiplying or allocating strings/integers.
                    if isinstance(node.op,ast.Mult) and (not isinstance(a,(int,float)) or not isinstance(b,(int,float))):return UNKNOWN
                    try:v=OPS[type(node.op)](a,b)
                    except (TypeError,ValueError,OverflowError):return UNKNOWN
                    if len(str(v))>4096:return UNKNOWN
                    results.append(frozenset([v]))
                return choices(*results)
        if isinstance(node,ast.Compare) and len(node.ops)==1 and type(node.ops[0]) in OPS:
            left,right=self.value(node.left,env),self.value(node.comparators[0],env)
            if isinstance(left,frozenset) and isinstance(right,frozenset):
                try:return choices(*(frozenset([OPS[type(node.ops[0])](a,b)]) for a,b in itertools.product(left,right)))
                except (TypeError,ValueError):pass
        if isinstance(node,ast.IfExp):
            test=self.condition(node.test,env)
            return self.value(node.body if test else node.orelse,env) if test is not None else choices(self.value(node.body,env),self.value(node.orelse,env))
        if isinstance(node,ast.JoinedStr):
            values=['']
            for part in node.values:
                if isinstance(part,ast.FormattedValue):
                    if part.format_spec is not None or part.conversion not in {-1,115}:return UNKNOWN
                    v=self.value(part.value,env)
                else:v=self.value(part,env)
                if not isinstance(v,frozenset) or len(values)*len(v)>8:return UNKNOWN
                values=[a+str(b) for a,b in itertools.product(values,v)]
                if any(len(v)>4096 for v in values):return UNKNOWN
            return frozenset(values)
        return UNKNOWN

    def condition(self,node,env):
        v=self.value(node,env)
        if isinstance(v,frozenset):
            outcomes={bool(x) for x in v}
            if len(outcomes)==1:return outcomes.pop()
        return None

    def constant_html(self, node, env):
        # Prove fixed formatting operands without evaluating format strings (a
        # width/precision in target code must never allocate scanner memory).
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
            if not isinstance(node.left, ast.Constant) or not isinstance(node.left.value, str):return False
            args = node.right.elts if isinstance(node.right, ast.Tuple) else [node.right]
        elif isinstance(node, ast.Call) and formatted_html(node):
            if node.keywords or any(isinstance(arg, ast.Starred) for arg in node.args):return False
            args = node.args
        else:
            value = self.value(node, env)
            return isinstance(value, frozenset) and bool(value)
        return all(isinstance(self.value(arg, env), frozenset) for arg in args)

    def inspect(self,node,env):
        # Every visit must agree, including repeated/unknown control paths.
        calls=[n for n in ast.walk(node) if isinstance(n,ast.Call)]
        def local_get(call):
            if not (isinstance(call.func,ast.Attribute) and isinstance(call.func.value,ast.Name)
                    and call.func.attr=='get' and not call.keywords):return False
            obj=env.get(call.func.value.id)
            return (isinstance(obj,LocalConfig) and len(call.args)==2
                    or isinstance(obj,dict) and len(call.args) in {1,2})
        if any(ast.unparse(n.func) not in {'eval','exec','os.system','subprocess.run','subprocess.call','subprocess.Popen'} and not local_get(n) for n in calls):
            for key,v in list(env.items()):
                if mutable(v):env[key]=UNKNOWN
        for expression in ast.walk(node):
            if self.html_context and formatted_html(expression):
                key = (HTML_RULE, expression.lineno)
                self.safe[key] = self.safe.get(key, True) and self.constant_html(expression, env)
                self.bases[key] = 'PROVEN_LOCAL_CONSTANT'
        for call in ast.walk(node):
            if not isinstance(call,ast.Call):continue
            rid=call_rule(call)
            if rid:
                val=self.value(call.args[0],env) if call.args else UNKNOWN
                key=(rid,call.lineno)
                guarded=val is STRING_LITERAL and rid=='ai-security.python.unsafe-eval'
                self.safe[key]=self.safe.get(key,True) and (guarded or isinstance(val,frozenset) and bool(val))
                self.bases[key]='EXACT_STRING_LITERAL_GUARD' if guarded else 'PROVEN_LOCAL_CONSTANT'
        # Unknown calls may mutate mapping objects. Keep already copied scalar
        # constants, but never trust a mutable container across a call.
        if any(isinstance(n,ast.Call) for n in ast.walk(node)):
            for key,v in list(env.items()):
                if mutable(v) and not all(local_get(n) for n in calls):env[key]=UNKNOWN
        if any(isinstance(n,ast.Call) and isinstance(n.func,ast.Name) and n.func.id in {'exec','locals','globals','vars'} for n in ast.walk(node)):
            env.clear()

    def merge_env(self,env,branches):
        env.clear()
        for name in set().union(*(b.keys() for b in branches)):
            env[name]=choices(*(b.get(name) for b in branches))

    def block(self,nodes,env):
        for node in nodes:
            self.tick()
            if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef)):continue
            if isinstance(node,(ast.Import,ast.ImportFrom)):
                if any(a.name=='*' for a in node.names):env.clear()
                else:
                    for alias in node.names:
                        env[alias.asname or alias.name.split('.')[0]]=CONFIG_MODULE if isinstance(node,ast.Import) and alias.name=='configparser' else UNKNOWN
                    for k,v in list(env.items()):
                        if mutable(v):env[k]=UNKNOWN
                continue
            if isinstance(node,ast.Expr) and self.config_write(node.value,env):continue
            if isinstance(node,ast.If):
                self.inspect(node.test,env);test=self.condition(node.test,env)
                guarded=self.literal_guard(node)
                if guarded is not None:
                    # Only the rejecting path exits. Never transfer this proof
                    # to an unrelated variable, a concatenation or a shell sink.
                    self.block(node.body,dict(env))
                    env[guarded]=STRING_LITERAL
                    continue
                if test is not None:
                    if self.block(node.body if test else node.orelse,env):return True
                else:
                    branches=[dict(env),dict(env)]
                    # Drop mutable aliases before branching.
                    for branch in branches:
                        for k,v in list(branch.items()):
                            if mutable(v):branch[k]=UNKNOWN
                    active=[b for body,b in zip((node.body,node.orelse),branches) if not self.block(body,b)]
                    if not active:return True
                    self.merge_env(env,active)
                continue
            if isinstance(node,ast.Match):
                value=self.value(node.subject,env)
                selected=None
                if isinstance(value,frozenset) and len(value)==1:
                    v=next(iter(value))
                    for case in node.cases:
                        if case.guard is not None:break
                        p=case.pattern
                        if isinstance(p,ast.MatchValue) and isinstance(p.value,ast.Constant) and p.value.value==v or isinstance(p,ast.MatchAs) and p.pattern is None and p.name is None:
                            selected=case.body;break
                        if not isinstance(p,ast.MatchValue):break
                if selected is not None:
                    if self.block(selected,env):return True
                else:
                    env.clear()
                    for case in node.cases:self.block(case.body,{})
                continue
            if isinstance(node,ast.Try):
                body=dict(env)
                self.block(node.body,body);self.block(node.orelse,body)
                for h in node.handlers:
                    self.block(h.body,{})
                # An exception may interrupt any assignment. Do not infer a
                # post-try value, including finally paths, from normal completion.
                env.clear();self.block(node.finalbody,{})
                continue
            if isinstance(node,(ast.For,ast.While,ast.With,ast.AsyncFor,ast.AsyncWith)):
                env.clear();self.block(node.body,{});env.clear();continue
            if isinstance(node,(ast.Assign,ast.AnnAssign,ast.AugAssign)):
                if isinstance(node, ast.AnnAssign) and node.value is None:
                    # An annotation-only statement has no RHS to inspect.
                    # Conservatively abandon current proofs, including complex
                    # annotated targets, and retain the engine's raw finding.
                    env.clear()
                    continue
                self.inspect(node.value,env)
                rhs=self.value(node.value,env)
                targets=node.targets if isinstance(node,ast.Assign) else [node.target]
                for target in targets:
                    if isinstance(target,ast.Name):
                        if isinstance(node,ast.AugAssign):rhs=self.value(ast.BinOp(left=target,op=node.op,right=node.value),env)
                        if mutable(rhs) and isinstance(node.value,ast.Name):
                            env[node.value.id]=UNKNOWN;rhs=UNKNOWN
                        env[target.id]=rhs
                    elif isinstance(target,ast.Subscript) and isinstance(target.value,ast.Name):
                        obj=env.get(target.value.id);key=self.value(target.slice,env)
                        if isinstance(obj,dict) and isinstance(key,frozenset) and len(key)==1:obj[next(iter(key))]=rhs
                        else:env[target.value.id]=UNKNOWN
                    else:env.clear()
                # Do not retain a parser after it escapes into a container or
                # attribute. A subsequent alias could mutate its options.
                if not (isinstance(node.value,ast.Call) and isinstance(node.value.func,ast.Attribute)
                        and node.value.func.attr in {'get','ConfigParser'}):
                    for child in ast.walk(node.value):
                        if isinstance(child,ast.Name) and isinstance(env.get(child.id),LocalConfig):env[child.id]=UNKNOWN
                continue
            self.inspect(node,env)
            if isinstance(node,(ast.Return,ast.Raise)):return True
            if not isinstance(node,(ast.Expr,ast.Pass)):env.clear()
        return False

    @staticmethod
    def literal_guard(node):
        # For built-in strings, enclosing quotes plus no interior quote permit
        # only a string expression (or a SyntaxError), never executable syntax.
        # Prefix/suffix checks alone are insufficient. Fail-open guards and
        # arbitrary sanitizer/helper names are deliberately not recognised.
        if node.orelse or not node.body or not isinstance(node.body[-1],(ast.Return,ast.Raise)):
            return None
        test=node.test
        if not isinstance(test,ast.BoolOp) or not isinstance(test.op,ast.Or) or len(test.values)!=3:
            return None
        for quote in ("'",'"'):
            for term in test.values:
                if not (isinstance(term,ast.UnaryOp) and isinstance(term.op,ast.Not)
                        and isinstance(term.operand,ast.Call) and isinstance(term.operand.func,ast.Attribute)
                        and isinstance(term.operand.func.value,ast.Name)):
                    continue
                name=term.operand.func.value.id
                expression=f'not {name}.startswith({quote!r}) or not {name}.endswith({quote!r}) or {quote!r} in {name}[1:-1]'
                expected=ast.parse(expression,mode='eval').body
                if {ast.dump(t) for t in test.values}=={ast.dump(t) for t in expected.values}:
                    return name
        return None

    def config_write(self,call,env):
        if not (isinstance(call,ast.Call) and isinstance(call.func,ast.Attribute)
                and isinstance(call.func.value,ast.Name)):return False
        name=call.func.value.id;obj=env.get(name)
        if not isinstance(obj,LocalConfig):return False
        if call.keywords or any(isinstance(n,ast.Call) for arg in call.args for n in ast.walk(arg)):
            for key,value in list(env.items()):
                if mutable(value):env[key]=UNKNOWN
            return True
        args=[self.value(arg,env) for arg in call.args]
        if any(mutable(value) for value in args):
            for key,value in list(env.items()):
                if mutable(value):env[key]=UNKNOWN
            return True
        section=one_string(args[0]) if args else None
        if call.func.attr=='add_section' and len(args)==1 and section not in {None,'DEFAULT'}:
            obj.sections.setdefault(section,{});return True
        key=one_string(args[1]) if len(args)>1 else None
        if call.func.attr=='set' and len(args)==3 and section in obj.sections and key is not None:
            obj.sections[section][key.lower()]=args[2];return True
        # read/read_dict, optionxform changes, unknown methods and dynamic keys
        # are not a proof of a fixed local option.
        env[name]=UNKNOWN;return True


def constant_evidence(text,seconds=.2):
    try:
        proof=Proof(text,seconds)
        calls={(call_rule(n),n.lineno) for n in ast.walk(proof.tree) if isinstance(n,ast.Call) and call_rule(n)}
        calls.update((HTML_RULE, n.lineno) for n in ast.walk(proof.tree) if formatted_html(n))
        return {key:proof.bases[key] for key,safe in proof.safe.items() if safe},calls
    except (ValueError,SyntaxError,RecursionError,TypeError,OverflowError):return set(),set()


def proven_constant_calls(text,seconds=.2):
    return set(constant_evidence(text,seconds)[0])


def filter_results(data,root,before,deadline):
    """Return a new result object, retaining raw alerts on any read/proof gap."""
    from .flow_core import Analysis,Limit
    from .local_evidence import snapshot_fingerprint
    reader=Analysis(root,max_files=80,max_bytes=2_000_000)
    proofs={};kept=[];suppressed=[]
    for item in data.get('results',[]):
        rid=item.get('check_id');name=item.get('path','').replace('\\','/')
        if rid not in RULES or time.monotonic()>=deadline:
            kept.append(item);continue
        if name not in proofs:
            proofs[name]=(set(),set())
            try:
                text=reader.read(name)
                proof=constant_evidence(text,min(.2,max(0,deadline-time.monotonic())))
                digest=reader.hashes[name]
                if before.get(name,{}).get('file_sha256')==digest==snapshot_fingerprint(root,name).get('file_sha256'):
                    proofs[name]=proof
            except (Limit,OSError,UnicodeError,ValueError):pass
        line=item.get('start',{}).get('line')
        end=item.get('end',{}).get('line',line)
        safe,calls=proofs[name]
        matches={key for key in calls if key[0]==rid and isinstance(line,int) and isinstance(end,int) and line<=key[1]<=end}
        if matches and matches<=set(safe):
            basis='EXACT_STRING_LITERAL_GUARD' if any(safe[key]=='EXACT_STRING_LITERAL_GUARD' for key in matches) else 'PROVEN_LOCAL_CONSTANT'
            suppressed.append(dict(rule_id=rid,file=name,line=line,basis=basis))
        else:kept.append(item)
    return dict(data,results=kept),suppressed
