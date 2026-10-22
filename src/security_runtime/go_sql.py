"""Small, bounded Go SQL flow model; no target execution or whole-program claims.

Only explicit input files, same-package direct calls and uniquely typed receivers
are resolved. The lexer preserves source lines; unsupported calls retain gaps.
"""
from dataclasses import dataclass, field
import hashlib
from pathlib import Path
import re
import time

from .capabilities import Capability
from .flow_core import Analysis, Limit
from .models import ScannerRun
from .progress import checkpoint
from .rule_catalog import RuleRecord
from .rulepacks import RulePackClass, RulePackDescriptor, RuleProvenance, ResolvedRulePack

VERSION = '1.0.0'
PACK_ID = 'ai-security-go-sql'
RULE_ID = 'ai-security.dataflow.go.sql-injection'
REFS = ('https://cwe.mitre.org/data/definitions/89.html',)
RULE = RuleRecord(RULE_ID, 'go', ('go',), 'sql-injection', ('CWE-89',), 'ERROR',
    'MEDIUM', 'BETA', 'net/http + database/sql; same-package resolved calls',
    PACK_ID, VERSION, REFS, {'origin':'FIRST_PARTY', 'author':'AI Security Runtime contributors',
    'created_at':'2026-10-22', 'references':list(REFS), 'license':'Apache-2.0', 'derived_from':''},
    'bounded-go-token-dataflow', 'security_runtime/go_sql.py', ('.go',), 'tests/test_go_sql.py')


def rule_pack():
    base = Path(__file__).parent
    digest = hashlib.sha256((base/'go_sql.py').read_bytes() + (base/'flow_core.py').read_bytes()).hexdigest()
    descriptor = RulePackDescriptor(PACK_ID, 'Bounded Go SQL dataflow', VERSION, 'AI Security Runtime',
        'AI Security Runtime contributors', 'Apache-2.0', 'https://www.apache.org/licenses/LICENSE-2.0',
        True, True, True, True, 'bundled source-only provider',
        RuleProvenance('FIRST_PARTY', 'AI Security Runtime contributors', '2026-10-22', REFS, 'Apache-2.0'),
        True, RulePackClass.FIRST_PARTY)
    return ResolvedRulePack(descriptor, base, digest, (RULE,))


@dataclass(frozen=True)
class Token:
    text: str
    line: int


TOKEN = re.compile(r'\s+|//[^\n]*|/\*[\s\S]*?\*/|"(?:\\.|[^"\\])*"|`[^`]*`|\'(?:\\.|[^\'\\])*\'|[^\W\d]\w*|\d+(?:\.\d+)?|:=|\+=|==|!=|<=|>=|&&|\|\||[^\s]', re.UNICODE)


def lex(text, check):
    tokens = []; line = 1
    for match in TOKEN.finditer(text):
        check()
        value = match[0]
        if value.isspace() or value.startswith(('//','/*')):
            if '\n' in value: tokens.append(Token(';', line))
        else:
            if value in {'"', "'", '`'}: raise Limit('GO_UNTERMINATED_LITERAL')
            tokens.append(Token(value, line))
        line += value.count('\n')
        if len(tokens) > 50_000: raise Limit('GO_TOKEN_BUDGET')
    return tokens


def pairs(tokens):
    result = {}; stack = []
    for i, token in enumerate(tokens):
        if token.text in {'(', '[', '{'}:
            stack.append(i)
            if len(stack) > 64: raise Limit('GO_NESTING_BUDGET')
        elif token.text in {')', ']', '}'}:
            if not stack or tokens[stack[-1]].text != {')':'(', ']':'[', '}':'{'}[token.text]:
                raise Limit('GO_UNBALANCED_SYNTAX')
            j = stack.pop(); result[j] = i; result[i] = j
    if stack: raise Limit('GO_UNBALANCED_SYNTAX')
    return result


def split(tokens, separator=','):
    result = []; start = 0; depth = 0
    for i, token in enumerate(tokens):
        if token.text in {'(', '[', '{'}: depth += 1
        elif token.text in {')', ']', '}'}: depth -= 1
        elif depth == 0 and token.text == separator:
            result.append(tokens[start:i]); start = i+1
    return [part for part in (*result, tokens[start:]) if part]


def spelling(tokens):
    return ''.join(t.text for t in tokens if t.text != ';')


@dataclass(frozen=True)
class Value:
    trace: tuple = ()
    kind: str = ''


def merge(*values):
    return Value(tuple(dict.fromkeys(step for v in values for step in v.trace))[:24],
                 values[0].kind if values and all(v.kind == values[0].kind for v in values) else '')


@dataclass
class Function:
    file: str
    package: tuple
    name: str
    receiver: tuple
    params: list
    result: str
    body: list
    line: int


class GoAnalysis:
    def __init__(self, root, files, *, seconds=3.0, max_files=64, max_steps=100_000, max_depth=2):
        self.deadline = time.monotonic() + seconds
        self.a = Analysis(Path(root).resolve(), max_files=max_files, max_bytes=2_000_000)
        self.files = tuple(files); self.max_steps = max_steps; self.max_depth = max_depth
        self.steps = 0; self.functions = {}; self.imports = {}; self.globals = {}
        self.issues = {}; self.gaps = set(); self.parsed = set()

    def tick(self):
        self.steps += 1
        if self.steps > self.max_steps: raise Limit('GO_STEP_BUDGET')
        if self.steps % 128 == 1:
            checkpoint()
            if time.monotonic() >= self.deadline: raise Limit('GO_TIME_BUDGET')

    def type_name(self, tokens, file):
        name = spelling(tokens).lstrip('*')
        if '.' in name:
            alias, _, member = name.partition('.')
            module = self.imports[file].get(alias, '')
            if (module, member) in {('net/http','Request'), ('database/sql','DB'), ('database/sql','Tx'), ('database/sql','Stmt')}:
                return module+'.'+member
            return ''
        return name if re.fullmatch(r'[^\W\d]\w*', name) else ''

    def parse(self, file):
        text = self.a.read(file)
        if '//go:build' in text or '// +build' in text: self.gaps.add((file,'GO_BUILD_CONSTRAINT'))
        tokens = lex(text, self.tick); links = pairs(tokens)
        imports = self.imports[file] = {}; globals_ = self.globals[file] = {}
        package = ''; i = 0
        while i < len(tokens):
            self.tick(); t = tokens[i].text
            if t == 'package' and i+1 < len(tokens): package = tokens[i+1].text
            if t == 'import':
                j = i+1
                if tokens[j].text == '(':
                    end = links[j]; body = tokens[j+1:end]
                else:
                    end = next((k for k in range(j,len(tokens)) if tokens[k].text==';'), len(tokens)); body=tokens[j:end]
                for item in split(body,';'):
                    if item and item[-1].text.startswith('"'):
                        module = item[-1].text[1:-1]
                        alias = item[0].text if len(item)>1 else module.rsplit('/',1)[-1]
                        imports[alias] = module
                i=end+1; continue
            if t == 'var' and i+2 < len(tokens):
                end=next((k for k in range(i+1,len(tokens)) if tokens[k].text==';'),len(tokens))
                declaration=tokens[i+1:end]
                if declaration and all(x.text not in {'(', '=', ','} for x in declaration):
                    globals_[declaration[0].text]=Value(kind=self.type_name(declaration[1:],file))
            if t == 'func':
                j=i+1; receiver=('', '')
                if tokens[j].text=='(':
                    end=links[j]; r=tokens[j+1:end]
                    receiver=(r[0].text,self.type_name(r[1:],file)) if r else ('','')
                    j=end+1
                name=tokens[j].text; j+=1
                if tokens[j].text!='(': raise Limit('GO_SIGNATURE_UNSUPPORTED')
                end=links[j]; params=[]
                for p in split(tokens[j+1:end]):
                    if len(p)<2: raise Limit('GO_GROUPED_PARAMETER_UNSUPPORTED')
                    params.append((p[0].text,self.type_name(p[1:],file)))
                j=end+1; body_start=j
                while body_start<len(tokens) and tokens[body_start].text not in {'{',';'}: body_start+=1
                if body_start>=len(tokens) or tokens[body_start].text!='{': raise Limit('GO_BODY_UNSUPPORTED')
                result=self.type_name(tokens[j:body_start],file)
                body_end=links[body_start]
                fn=Function(file,(str(Path(file).parent),package),name,receiver,params,result,
                            tokens[body_start+1:body_end],tokens[i].line)
                self.functions.setdefault((fn.package,receiver[1],name),[]).append(fn)
                i=body_end+1; continue
            if t=='{': i=links[i]+1
            else: i+=1
        self.parsed.add(file)

    def expression(self, ts, env, fn, depth, active):
        self.tick(); ts=[t for t in ts if t.text!=';']
        if not ts: return Value()
        links=pairs(ts)
        if ts[0].text=='(' and links[0]==len(ts)-1: return self.expression(ts[1:-1],env,fn,depth,active)
        parts=split(ts,'+')
        if len(parts)>1: return merge(*(self.expression(p,env,fn,depth,active) for p in parts))
        if ts[-1].text==')':
            opening=links[len(ts)-1]; head=ts[:opening]
            args=[self.expression(p,env,fn,depth,active) for p in split(ts[opening+1:-1])]
            if len(head)>=3 and head[-2].text=='.':
                method=head[-1].text; base=head[:-2]
                obj=self.expression(base,env,fn,depth,active)
                if obj.kind=='net/http.Request' and method in {'FormValue','PostFormValue'} or obj.kind=='request-values' and method=='Get':
                    return Value(((fn.file,ts[0].line,'SOURCE'),))
                if obj.kind=='request-url' and method=='Query': return Value(kind='request-values')
                if spelling(base) not in env and self.imports[fn.file].get(spelling(base))=='fmt' and method in {'Sprintf','Sprint','Sprintln'}:
                    return merge(*args)
                if obj.kind in {'database/sql.DB','database/sql.Tx'} and method in {'Query','Exec','QueryRow','Prepare','QueryContext','ExecContext','QueryRowContext','PrepareContext'}:
                    index=1 if method.endswith('Context') else 0
                    if len(args)>index and args[index].trace:
                        self.issues[(fn.file,ts[0].line)]=(*args[index].trace,(fn.file,ts[0].line,'SINK'))
                    return Value(kind='database/sql.Stmt' if method.startswith('Prepare') else '')
                if obj.kind=='database/sql.Stmt': return Value()  # Bound values do not form SQL text.
                candidates=self.functions.get((fn.package,obj.kind,method),[]) if obj.kind else []
            else:
                candidates=[] if spelling(head) in env else self.functions.get((fn.package,'',spelling(head)),[])
            candidates = [candidate for candidate in candidates if candidate.file in self.parsed]
            if len(candidates)==1:
                callee=candidates[0]
                if not any(v.trace for v in args): return Value(kind=callee.result)
                if depth>=self.max_depth or (callee.file,callee.line) in active:
                    self.gaps.add((fn.file,'GO_CALL_DEPTH_OR_RECURSION')); return merge(*args)
                if len(args)!=len(callee.params):
                    self.gaps.add((fn.file,'GO_ARGUMENTS_UNRESOLVED')); return merge(*args)
                values=[Value((*v.trace,(fn.file,ts[0].line,'RESOLVED_CALL')),v.kind) if v.trace else v for v in args]
                return self.invoke(callee,values,depth+1,active)
            if any(v.trace for v in args): self.gaps.add((fn.file,'GO_CALL_UNRESOLVED'))
            return merge(*args)
        if len(ts)>=3 and ts[-2].text=='.':
            obj=self.expression(ts[:-2],env,fn,depth,active)
            if obj.kind=='net/http.Request' and ts[-1].text=='URL': return Value(kind='request-url')
            if obj.trace or obj.kind=='net/http.Request':self.gaps.add((fn.file,'GO_FIELD_FLOW_UNSUPPORTED'))
            return Value(obj.trace)
        if ts[0].text=='&': return self.expression(ts[1:],env,fn,depth,active)
        if len(ts)>=3 and ts[1].text=='{' and links[1]==len(ts)-1: return Value(kind=ts[0].text)
        if len(ts)==1: return env.get(ts[0].text,Value())
        # Do not manufacture clean data for an unsupported expression.
        value=merge(*(env.get(t.text,Value()) for t in ts))
        if value.trace: self.gaps.add((fn.file,'GO_EXPRESSION_UNSUPPORTED'))
        return value

    def block(self, tokens, env, fn, depth, active):
        links=pairs(tokens); i=0; returns=[]
        while i<len(tokens):
            self.tick()
            if tokens[i].text==';': i+=1; continue
            if tokens[i].text in {'if','for','switch','select'}:
                j=i+1
                while j<len(tokens) and tokens[j].text!='{':
                    if tokens[j].text in {'(', '['}: j=links[j]+1
                    else: j+=1
                if j==len(tokens): raise Limit('GO_CONTROL_UNSUPPORTED')
                if tokens[i].text!='if': self.gaps.add((fn.file,'GO_LOOP_OR_SWITCH_PARTIAL'))
                before=dict(env); branch=dict(env)
                self.block(tokens[i+1:j],branch,fn,depth,active)
                returns.extend(self.block(tokens[j+1:links[j]],branch,fn,depth,active))
                i=links[j]+1
                # Merge both paths; an unmodelled predicate never sanitizes input.
                for name in set(before)|set(branch): env[name]=merge(before.get(name,Value()),branch.get(name,Value()))
                continue
            if tokens[i].text=='else': i+=1; continue
            if tokens[i].text=='{':
                branch=dict(env);returns.extend(self.block(tokens[i+1:links[i]],branch,fn,depth,active))
                for name in set(env)|set(branch):env[name]=merge(env.get(name,Value()),branch.get(name,Value()))
                i=links[i]+1;continue
            end=i
            while end<len(tokens) and tokens[end].text!=';':
                if tokens[end].text in {'(', '[', '{'}: end=links[end]+1
                else: end+=1
            statement=tokens[i:end]; i=end+1
            if not statement: continue
            if statement[0].text in {'const','var'} and len(statement)>1 and statement[1].text=='(':
                self.gaps.add((fn.file,'GO_GROUPED_DECLARATION_UNSUPPORTED'));continue
            if statement[0].text=='return':
                returns.append(self.expression(statement[1:],env,fn,depth,active)); break
            assignment=next((k for k,t in enumerate(statement) if t.text in {':=','=','+='}),None)
            if assignment is not None:
                left=statement[:assignment]; right=statement[assignment+1:]
                value=self.expression(right,env,fn,depth,active)
                names=split(left)
                for n,target in enumerate(names):
                    if len(target)!=1:
                        self.gaps.add((fn.file,'GO_ASSIGNMENT_UNSUPPORTED'));continue
                    name=target[0].text
                    if name=='_':continue
                    assigned=value if n==0 else Value()
                    static=self.globals[fn.file].get(name,Value()).kind if statement[assignment].text=='=' else ''
                    if static: assigned=Value(assigned.trace,static)
                    env[name]=merge(env.get(name,Value()),assigned) if statement[assignment].text=='+=' else assigned
            else: self.expression(statement,env,fn,depth,active)
        return returns

    def invoke(self, fn, args, depth=0, active=()):
        env=dict(self.globals[fn.file])
        for (name,kind),value in zip(fn.params,args): env[name]=Value(value.trace,kind or value.kind)
        if fn.receiver[0]: env[fn.receiver[0]]=Value(kind=fn.receiver[1])
        values=self.block(fn.body,env,fn,depth,(*active,(fn.file,fn.line)))
        result=merge(*values)
        return Value(result.trace,fn.result or result.kind)

    def run(self):
        for file in self.files[self.a.max_files:]: self.gaps.add((file,'GO_FILE_BUDGET'))
        for file in self.files[:self.a.max_files]:
            try: self.tick(); self.parse(file)
            except (Limit,OSError,UnicodeError,ValueError,IndexError,RecursionError) as exc:
                self.gaps.add((file,str(exc) if isinstance(exc,Limit) else type(exc).__name__))
        for candidates in self.functions.values():
            if len(candidates)>1:
                for fn in candidates: self.gaps.add((fn.file,'GO_AMBIGUOUS_FUNCTION'))
                continue
            fn=candidates[0]
            if fn.file not in self.parsed: continue
            if not any(kind=='net/http.Request' for _,kind in fn.params): continue
            try: self.invoke(fn,[Value() for _ in fn.params])
            except (Limit,ValueError,IndexError,RecursionError) as exc:
                self.gaps.add((fn.file,str(exc) if isinstance(exc,Limit) else type(exc).__name__))
        return self


@dataclass
class GoSQLPlan:
    pack: object
    files: tuple
    parsed: set = field(default_factory=set)
    gaps: set = field(default_factory=set)
    rules: tuple = (RULE,)

    def coverage(self,status='PLANNED'):
        state='PLANNED' if status=='PLANNED' else 'PARTIAL' if self.gaps or set(self.files)!=self.parsed else 'EXECUTED'
        executed=bool(self.parsed)
        return dict(engine='native-go-sql',rule_pack_id=PACK_ID,rule_pack_version=VERSION,rule_pack_checksum=self.pack.checksum,
            status=state,total_selected=int(bool(self.files)),total_executed=int(executed),scope_files=list(self.files),
            total_files=len(self.files),verification_scope_complete=False,whole_program_reachability='NOT_IMPLEMENTED',
            per_language={'go':dict(available_rules=1,selected_rules=1,executed_rules=int(executed),
                selected_rule_ids=[RULE_ID],executed_rule_ids=[RULE_ID] if executed else [],target_files=len(self.files),
                scanned_files=len(self.parsed),status=state)},
            limitations=['Same-package net/http sources to database/sql text; direct calls and uniquely typed receivers only.',
                'At most 2 call edges, 64 explicit files, 2 MB, 100000 steps and a 3-second soft deadline per scan.',
                'No interface dispatch, reflection, arbitrary imports, full Go grammar or complete program coverage.',
                'Feature scans use only captured input/context files; missing helpers remain unresolved.'])


class GoSQLScanner:
    name = scanner_id = engine_id = 'native-go-sql'
    display_name = 'Go SQL 有界数据流分析'
    capabilities = frozenset({Capability.CODE_SAST})
    supported_languages = frozenset({'Go'})
    supported_ecosystems = frozenset()
    filter_changed_lines = False
    verification_offline = True
    verification_scope_complete = False

    def required_engines(self): return ()
    def version(self): return VERSION
    def supports(self,profile,context): return context.mode in {'release','feature'} and any(f.endswith('.go') for f in context.files)
    def plan_rules(self,profile,context):
        return GoSQLPlan(rule_pack(),tuple(dict.fromkeys(f for f in (*context.files,*context.context_files) if f.endswith('.go'))))
    def normalize(self,raw,normalizer): raise ValueError('Fresh local Go evidence required')

    def scan(self,context,normalizer):
        start=time.monotonic();plan=context.rule_plan if isinstance(context.rule_plan,GoSQLPlan) else self.plan_rules(None,context)
        analysis=GoAnalysis(context.root,plan.files).run()
        stable=analysis.a.stable();found=[]
        plan.parsed.update(analysis.parsed);plan.gaps.update(analysis.gaps)
        if not stable: plan.gaps.add(('', 'SOURCE_CHANGED'));plan.parsed.clear()
        if stable:
            for (file,line),trace in sorted(analysis.issues.items()):
                anchor=(file,line) if file in context.files else next(((f,n) for f,n,_ in trace if f in context.files),None)
                if anchor is None:continue
                finding=normalizer.make(scanner=self.name,category='sql-injection',title='请求输入经本地调用进入 SQL 文本',
                    description='有界 Go 分析识别到请求输入进入 database/sql 查询文本；参数绑定与查询文本分别处理。',
                    severity='HIGH',confidence='MEDIUM',file_path=anchor[0],line=anchor[1],rule_id=RULE_ID,
                    evidence='request -> resolved same-package call -> SQL text')
                finding.technical_details.update(engine=self.name,rule_pack=PACK_ID,rule_pack_version=VERSION,rule_version=VERSION,
                    rule_pack_checksum=plan.pack.checksum,cwe=['CWE-89'],verification_scope_complete=False,
                    dataflow_trace=[dict(file=f,line=n,kind=k) for f,n,k in trace],context_hashes=dict(analysis.a.hashes),
                    evidence_locator=dict(file_sha256=analysis.a.hashes.get(anchor[0]),snapshot_reason=None))
                found.append(finding)
        coverage=plan.coverage('SUCCESS')
        run=ScannerRun(self.name,VERSION,'PARTIAL' if plan.gaps else 'SUCCESS',round((time.monotonic()-start)*1000),len(found),
            provider=self.name,capabilities=(Capability.CODE_SAST,),coverage_contract='PARTIAL',rule_coverage=coverage,
            coverage_notes=coverage['limitations'],scanner_diagnostics=dict(parsed_files=len(analysis.parsed),
                abstract_steps=analysis.steps,soft_budget_seconds=3,max_call_depth=2,source_stable=stable,
                context_gaps=[dict(file=f,reason=r) for f,r in sorted(plan.gaps)][:30],context_gaps_truncated=len(plan.gaps)>30))
        return found,run
