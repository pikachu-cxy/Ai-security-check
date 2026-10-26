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
# These names are accepted only in authenticated prior ownership, never shipped
# or adopted from matching bytes in an unmanaged Skill directory.
RETIRED_METHODS = frozenset({'references/quick-task-review.md', 'references/quick-task-review-v2.md'})


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode('utf-8')


def digest(content):
    return hashlib.sha256(content).hexdigest()


def repair_impact_reference():
    from .guidance.host_guidance import REPAIR_IMPACT_GUIDANCE

    original_task_ref = 'ts1-' + '0' * 32
    original_finding_id = 'tc1-' + '1' * 32
    assessment_ref = 'ria1-' + '2' * 32
    evidence_ref = 'ri-evidence-' + '3' * 32
    examples = [
        ('准备原生风险的具体方案', dict(tool='prepare_repair_impact', arguments=dict(
            source=dict(kind='HOST_TASK_RISK', task_ref=original_task_ref,
                        finding_id=original_finding_id, origin_review_revision=1),
            proposal=dict(security_goal='拒绝未获授权的文档读取与下载。',
                summary='读取入口复用所有者或共享成员的权限规则。',
                changes=[dict(file_path='documents.py', start_line=1, end_line=3,
                              reason='在返回内容前复用现有 can_read 权限检查。')],
                preserve=['所有者和共享成员读取及下载获准文档。'])))),
        ('用户已明确修复：尽早登记原生修复意图', dict(tool='prepare_task_risk_fix', arguments=dict(
            task_ref=original_task_ref, finding_id=original_finding_id,
            origin_review_revision=1, impact_ref=assessment_ref,
            user_requested=True))),
        ('A2 局部方案：保存有限分析及非阻断范围未知', dict(tool='submit_repair_impact', arguments=dict(
            assessment_ref=assessment_ref, coverage='REVIEWED',
            impacts=[dict(kind='EXPECTED_SECURITY_RESTRICTION', summary='其他用户的读取与下载将被拒绝。',
                          evidence_refs=[evidence_ref]),
                     dict(kind='NO_ADDITIONAL_CHANGE_IDENTIFIED',
                           summary='已读四文件的权限与下载调用链中，所有者和共享成员继续使用同一 can_read；参数、返回结构和下载委托关系不变。',
                           evidence_refs=[evidence_ref])],
            unknowns=[dict(summary='项目外仓储实现、上游身份来源和异常显示未提供，本次局部修复不改变这些边界；全局兼容性尚未证明。',
                critical=False, classification='SCOPE_LIMITATION',
                decision_basis='当前方案仅复用既有 can_read；已查正常所有者和共享成员路径未发现额外变化，也没有合法记录缺字段的具体依据。外部实现缺失本身不改变这一局部方案，保留范围限制而不推断全局安全。',
                evidence_refs=[evidence_ref])]))),
        ('保存未完成分析', dict(tool='submit_repair_impact', arguments=dict(
            assessment_ref=assessment_ref, coverage='PARTIAL', impacts=[],
            unknowns=[dict(summary='共享成员权限的必要调用路径尚未读完。', critical=True,
                           evidence_refs=[])]))),
        ('影响提交通过后重试同一原生准备', dict(tool='prepare_task_risk_fix', arguments=dict(
            task_ref=original_task_ref, finding_id=original_finding_id,
            origin_review_revision=1, impact_ref=assessment_ref,
            user_requested=True))),
        ('用户明确暂停原修复或切换开发', dict(tool='cancel_task_risk_fix', arguments=dict(
            task_ref=original_task_ref, finding_id=original_finding_id, user_requested=True))),
        ('真实必要上下文阻断对照（替代提交，并非 A2 已知事实）', dict(
            tool='submit_repair_impact', arguments=dict(
                assessment_ref=assessment_ref, coverage='REVIEWED',
                impacts=[dict(kind='UNDETERMINED',
                    summary='对照例已确认合法共享成员下载可使用精简文档投影，但尚不能确定当前调用所选分支，无法判定新增 can_read 是否会造成缺字段异常。',
                    decision_basis='正常共享成员下载路径存在具体的精简投影分支；当前方案依赖该分支可能未提供的权限字段。必须先查明实际投影选择，才能决定复用当前方案还是补齐返回契约。',
                    evidence_refs=[evidence_ref])],
                unknowns=[dict(
                    summary='当前合法下载调用选择完整权限字段还是精简投影尚未核对。',
                    critical=True, classification='BLOCKING_CONTEXT',
                    decision_basis='具体正常路径是共享成员下载；缺少实际仓储投影选择。完整投影可继续既有 can_read，精简投影则须先调整数据契约或方案；下一步读取投影选择的调用与返回契约，未补齐前不编辑。',
                    evidence_refs=[evidence_ref])]))),
    ]
    rendered = '\n\n'.join('### ' + title + '\n\n```json\n' +
        json.dumps(value, ensure_ascii=False, indent=2) + '\n```' for title, value in examples)
    return ('# 修复影响分析\n\n' + REPAIR_IMPACT_GUIDANCE +
        '\n## 字段与调用示例\n\n以下引用仅演示字段形状，必须替换为原记录和本评估读取返回的真实引用；'
        'SessionStart 已提供 session_ref 时，每次调用还须原样携带它及当前 workspace_path。'
        '只问影响时不调用 prepare_task_risk_fix／cancel_task_risk_fix；用户已明确修复时，先取评估引用并尽早登记 WAITING 意图，'
        '沿原评估读取／提交，再重试同一准备入口取得基线。PARTIAL 是保存未完成结果的替代分支。'
        '示例不独立授权修复，不表示示例项目已经核查。空 unknowns 只适用于实际没有剩余未知的范围。'
        '示例中的 classification／decision_basis 仅在当前实际连接声明 repair_impact_unknowns=repair-impact-unknowns-v1 时使用；'
        '旧连接不发送新字段，仍按原 critical 与门槛保存事实，不用省略或重命名未知来伪造通过。'
        'A2 的外部范围未知不同时登记为 UNDETERMINED；对照例的具体分支事实必须由实际读取证据支持，不能照抄到 A2。'
        '未读 PARTIAL 例尚无可引用材料时沿用 legacy critical=true，不虚构 evidence_ref。'
        'PARTIAL 或 WAITING 都不表示可编辑；只有准备返回 ready_for_host_fix=true 才进入原范围编辑。\n\n' + rendered + '\n')


def skill_entrypoint():
    from .guidance.host_guidance import HOST_INSTRUCTIONS
    return ('---\nname: ai-security-review\ndescription: Check source/config development before the final summary, or use AI Security Runtime for requested audits and explicitly authorized selected-risk fixes. Ordinary chat and read-only questions do not start checks. Requires connected ai_security_runtime MCP.\n---\n\n# Security review\n\n' + HOST_INSTRUCTIONS + '\n').encode('utf-8')


def generated_skill_file(name):
    """Single renderer shared by live guidance and shipped Markdown copies."""
    from .guidance.host_guidance import RUNTIME_WORKFLOW
    from .guidance.host_guidance import RISK_DECISION_WORKFLOW
    if name == 'SKILL.md':
        return skill_entrypoint()
    if name == 'references/runtime-workflow.md':
        return ('# Canonical Runtime workflow\n\n' + RUNTIME_WORKFLOW + '\n').encode('utf-8')
    if name == 'references/risk-decisions.md':
        return ('# 风险交互与用户处置\n\n' + RISK_DECISION_WORKFLOW).encode('utf-8')
    if name == 'references/repair-impact.md':
        return repair_impact_reference().encode('utf-8')
    if name == 'references/development-check.md':
        from .guidance.development_check_guidance import DEVELOPMENT_CHECK_GUIDANCE
        return (DEVELOPMENT_CHECK_GUIDANCE + '\n').encode('utf-8')
    raise ValueError('Unsupported generated Skill file')


GENERATED_FILES = ('SKILL.md', 'references/runtime-workflow.md',
                   'references/risk-decisions.md', 'references/repair-impact.md',
                   'references/development-check.md')


def skill_files():
    source = Path(__file__).parent / 'skills' / NAME
    return {name: (source / name).read_bytes() for name in (
        'agents/openai.yaml', 'references/deep-audit.md', 'references/quick-task-review-v3.md')} | {
        name: generated_skill_file(name) for name in GENERATED_FILES}


def skill_content_manifest(contents=None):
    """Shared identity for shipped managed bytes; no installation or state I/O."""
    files = skill_files() if contents is None else contents
    hashes = {name: digest(raw) for name, raw in sorted(files.items())}
    return dict(contract=CONTRACT, content_sha256=digest(encode(hashes)), files=hashes)


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
                    or not isinstance(value['files'], dict)
                    or not isinstance(value.get('previous', {}), dict)
                    or not isinstance(value.get('cleanup', {}), dict)
                    or not BASE_FILES <= set(value['files']) <= set(self.expected) | RETIRED_METHODS
                    or set(value.get('previous', {})) - (set(self.expected) | RETIRED_METHODS)
                    or set(value.get('cleanup', {})) - RETIRED_METHODS
                    or set(value.get('cleanup', {})) & set(value['files'])
                    or value.get('cleanup') and value['phase'] != 'UPDATING'): raise ValueError()
            for content_hash in [*value['files'].values(), *value.get('previous', {}).values(),
                                 *value.get('cleanup', {}).values()]:
                if not isinstance(content_hash, str) or len(content_hash) != 64 or any(c not in '0123456789abcdef' for c in content_hash): raise ValueError()
            return value
        except (ValueError, TypeError, KeyError):
            raise ValueError('SKILL_OWNERSHIP_INVALID') from None

    def status(self):
        from .compatibility import requirements
        try:
            no_links(self.root)
            manifest = self.manifest()
            preserved_retired = []
            if manifest is None:
                state = 'USER_MANAGED' if self.root.exists() and any(self.root.iterdir()) else 'NOT_INSTALLED'
            else:
                modified = []
                missing = []
                for name, content_hash in (manifest['files'] | manifest.get('cleanup', {})).items():
                    raw = self.read(self.root / name)
                    if raw is None:
                        # A recorded deletion may already have completed before
                        # an interrupted cleanup; it is not a missing new file.
                        if name not in manifest.get('cleanup', {}): missing.append(name)
                    elif digest(raw) not in {content_hash, manifest.get('previous', {}).get(name)}:
                        if name in RETIRED_METHODS and name not in self.expected:
                            preserved_retired.append(name)
                        else:
                            modified.append(name)
                # Adding a shipped file must not adopt content outside old ownership.
                for name in set(self.expected) - set(manifest['files']):
                    if self.read(self.root / name) is not None:
                        modified.append(name)
                state = ('USER_MODIFIED' if modified else 'REPAIR_REQUIRED' if missing or manifest['phase']=='UPDATING'
                         else 'INSTALLED' if manifest['files']=={n:digest(b) for n,b in self.expected.items()}
                         else 'UPGRADE_AVAILABLE')
            return {'skill':NAME, 'status':state, 'path':str(self.root),
                    'compatibility_requirements':requirements(),
                    'requirements_scope':'DECLARATION_NOT_HOST_TOOL_DISCOVERY',
                    'contract':CONTRACT, 'runtime_version':__version__,
                    'shipped_content_sha256':skill_content_manifest(self.expected)['content_sha256'],
                    'installed_content_sha256':(digest(encode(manifest['files']))
                        if manifest and not preserved_retired and state in {'INSTALLED', 'UPGRADE_AVAILABLE'} else None),
                    'preserved_retired_files':sorted(preserved_retired),
                    'host_discovery':'HOST_MANAGED; restart if not visible'}
        except (OSError, ValueError):
            return {'skill':NAME, 'status':'OWNERSHIP_CONFLICT', 'reason':'SKILL_PATH_OR_OWNERSHIP_INVALID',
                    'compatibility_requirements':requirements(),
                    'requirements_scope':'DECLARATION_NOT_HOST_TOOL_DISCOVERY'}

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
        with HookStateStore(self.state / 'locks').lock(self.root, wait_seconds=0) as acquired:
            if not acquired: raise ValueError('SKILL_BUSY')
            before = self.status()
            if before['status'] in {'USER_MANAGED','USER_MODIFIED','OWNERSHIP_CONFLICT'}:
                return before | {'action':action,'changed':False,'reason':'USER_CONTENT_PRESERVED'}
            manifest = self.manifest()
            owned = (manifest['files'] | manifest.get('cleanup', {})) if manifest else {}
            originals = {name:self.read(self.root / name) for name in set(self.expected) | set(owned)}
            detached = set()
            # A snapshot taken after status must still match signed ownership.
            # Never re-sign a concurrent user edit as the new previous content.
            for name, raw in originals.items():
                if raw is not None and (name not in owned or digest(raw) not in {
                        owned[name], manifest.get('previous', {}).get(name)}):
                    if name in RETIRED_METHODS and name not in self.expected:
                        detached.add(name)
                    else:
                        raise ValueError('SKILL_CHANGED_DURING_UPDATE')
            owned = {name:content_hash for name,content_hash in owned.items() if name not in detached}
            if action == 'remove':
                if manifest:
                    for name in owned:
                        raw = originals[name]
                        if raw is not None:
                            if self.read(self.root / name) != raw: raise ValueError('SKILL_CHANGED_DURING_UPDATE')
                            self.write(self.root / name, None)
                    for directory in ('agents','references',''):
                        try: (self.root / directory).rmdir()
                        except OSError: pass  # Never remove extra user files.
                    self.write(self.state / 'ownership.json', None)
                return {'skill':NAME,'status':'REMOVED','changed':bool(manifest), 'user_files_preserved':True,
                        'preserved_retired_files':sorted(detached)}
            desired = {name:digest(raw) for name,raw in self.expected.items()}
            if before['status']=='INSTALLED': return before | {'action':action,'changed':False}
            value = {'skill':NAME,'contract':CONTRACT,'scope':'USER','root_identity':self.state.name,
                     'runtime_version':__version__,'phase':'UPDATING','files':desired,
                      'previous':{name:digest(raw) for name,raw in originals.items()
                                  if name in self.expected and raw is not None},
                      'cleanup':{name:digest(originals[name]) if originals[name] is not None else content_hash
                                 for name,content_hash in owned.items()
                                 if name in RETIRED_METHODS and name not in self.expected}}
            self.save(value)
            for name, raw in self.expected.items():
                if self.read(self.root / name) != originals[name]: raise ValueError('SKILL_CHANGED_DURING_UPDATE')
                self.write(self.root / name,raw)
                if self.read(self.root / name) != raw: raise ValueError('SKILL_WRITE_FAILED')
            for name in value['cleanup']:
                if self.read(self.root / name) != originals[name]: raise ValueError('SKILL_CHANGED_DURING_UPDATE')
                self.write(self.root / name, None)
                if self.read(self.root / name) is not None: raise ValueError('SKILL_WRITE_FAILED')
            if (any(self.read(self.root / name) != raw for name,raw in self.expected.items())
                    or any(self.read(self.root / name) is not None for name in value['cleanup'])):
                raise ValueError('SKILL_CHANGED_DURING_UPDATE')
            self.save(value | {'phase':'COMMITTED','previous':{},'cleanup':{}})
            return self.status() | {'action':action,'changed':True,'user_files_preserved':True,
                                    'preserved_retired_files':sorted(detached)}
