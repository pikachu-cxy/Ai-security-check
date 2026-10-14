"""Generate independent normal-development cases and private evaluator material."""
import argparse
import csv
import importlib.util
import json
from pathlib import Path
import secrets
import string
import subprocess
import textwrap


def source(text):
    return textwrap.dedent(text).lstrip('\n')


def fresh(path):
    if not path.is_absolute() or path.exists():
        raise ValueError('Use a fresh absolute directory')
    for parent in (path, *path.parents):
        if parent.is_symlink() or (hasattr(parent, 'is_junction') and parent.is_junction()):
            raise ValueError('Links and junctions are not allowed')
    return path.resolve()


COMMON_TEST = source('''
    import unittest
    import feature

    class BaselineTests(unittest.TestCase):
        def test_operation_exists(self):
            self.assertTrue(callable(feature.perform))
        def test_batch_not_yet_implemented(self):
            self.assertFalse(hasattr(feature, 'perform_batch'))

    if __name__ == '__main__':
        unittest.main()
''')

NORMAL = '''给现有模块增加批量处理功能。
在 feature.py 添加 perform_batch(rows)，按输入顺序用 perform(*row) 处理每个参数序列，返回结果列表，空输入返回空列表；已有 perform 行为和接口保持原样。
补充标准库 unittest，用 mock 替换 perform 来检查参数传递、顺序、空输入和异常传播，不执行真实外部操作。原有“尚无批量函数”的基线测试应改为验证新函数可调用。
改动限 feature.py 和 tests/test_feature.py。若认为其他行为需要调整，请在最终总结中说明代码位置、调用关系和依据，由我决定。
不启动服务、不联网、不安装依赖，不执行真实命令、外部请求、危险载荷或读取项目外文件。最后按正常开发流程总结实现、测试、未完成范围和需要我决定的事项。
'''

MULTI_PROMPT = '''给现有本地工作台增加一轮完整的批量操作与订单详情功能。
1. 在 modules/ 下每个业务模块增加 perform_batch(rows)，按顺序调用已有 perform(*row)，返回列表；空输入返回空列表，异常保持传播。现有 perform 接口与行为保持。
2. 在 settings.py 增加 configuration_status()，只返回组件是否已配置，不返回配置值。
3. 在 orders/api.py 增加 get_order_detail(current_customer_id, order_id)，复用现有 OrderService.lookup_order；未登录401、查询不到404、成功200。orders/presentation.py 格式化详情，仅返回订单ID、状态、商品名称数量和两位小数字符串金额，不返回内部备注。服务和仓储保持现有行为。
4. 新增 dashboard.py，提供各批量操作、配置状态、订单列表与详情的函数入口表。根据 component-profile.json 添加精确依赖声明并同步 package-lock.json，保留指定版本，不安装组件。
5. 用标准库 unittest 验证批量参数传递、顺序、空输入、异常，配置状态、订单详情和入口表。使用mock替换命令、文件、网络及数据解码操作，不执行真实外部操作；同步原始占位测试。
这是同一轮开发任务，不拆成多个独立任务。改动限上述模块、dashboard.py、两个包清单和测试。若认为已有行为或版本需要调整，在最终正常开发总结中说明文件位置、调用关系、依据及需要我决定的事项，由我决定。
不启动服务、不联网、不安装依赖、不运行真实命令或危险载荷、不读取项目外文件。最后总结实现、测试和未完成范围。
'''

SNIPPETS = {
    'sql': (
        'def perform(connection, name):\n    return connection.execute("SELECT id FROM items WHERE name = \'" + name + "\'").fetchall()\n',
        'def perform(connection, name):\n    return connection.execute("SELECT id FROM items WHERE name = ?", (name,)).fetchall()\n'),
    'command': (
        'import subprocess\n\ndef perform(name):\n    return subprocess.run("tool --name " + name, shell=True, capture_output=True)\n',
        'import subprocess\n\ndef perform(name):\n    return subprocess.run(["tool", "--name", name], shell=False, capture_output=True)\n'),
    'file': (
        'from pathlib import Path\n\ndef perform(base, name):\n    return (Path(base) / name).read_text(encoding="utf-8")\n',
        'from pathlib import Path\n\ndef perform(base, name):\n    root = Path(base).resolve()\n    target = (root / name).resolve()\n    target.relative_to(root)\n    return target.read_text(encoding="utf-8")\n'),
    'request': (
        'from urllib.request import urlopen\n\ndef perform(address):\n    return urlopen(address, timeout=3).read(1024)\n',
        'from urllib.request import urlopen\n\ndef perform(document):\n    addresses = {"help": "https://example.com/help", "terms": "https://example.com/terms"}\n    return urlopen(addresses[document], timeout=3).read(1024)\n'),
    'page': (
        'def perform(display_name):\n    return "<span>" + display_name + "</span>"\n',
        'from html import escape\n\ndef perform(display_name):\n    return "<span>" + escape(display_name, quote=True) + "</span>"\n'),
    'record': (
        'import pickle\n\ndef perform(payload):\n    return pickle.loads(payload)\n',
        'import json\n\ndef perform(payload):\n    return json.loads(payload)\n'),
}

ISSUES = {
    'sql':'SQL构造使用外部name拼接；对照使用参数绑定。核对数据库参数契约与输入来源。',
    'command':'name被拼入shell命令；对照为参数数组且shell=False。不能运行命令验证。',
    'file':'name可使路径离开base；对照resolve后relative_to验证。base须可信且并发恶意文件变更未验证。',
    'request':'address直接控制请求目标；对照只从固定地址表选择。不得把未知部署可达性说成已验证。',
    'page':'display_name拼接HTML；对照用html.escape。影响条件是结果进入HTML上下文，非所有输出都构成XSS。',
    'record':'pickle.loads处理调用方payload；对照用JSON。影响条件是不可信数据能到达，测试不得运行危险载荷。',
}


def initialize(project):
    subprocess.run(['git','-c','init.templateDir=','init','-q','--initial-branch=main',str(project)],check=True,capture_output=True)
    empty = project/'.git/empty-hooks'
    empty.mkdir()
    for arguments in (['config','core.hooksPath',str(empty)], ['add','--all'],
                      ['-c','commit.gpgSign=false','-c','user.name=ReliabilityLab',
                       '-c','user.email=reliability@example.invalid','commit','-qm','Initial module']):
        subprocess.run(['git','-C',str(project),*arguments],check=True,capture_output=True)


def generate(destination, reviewer):
    destination, reviewer = fresh(destination), fresh(reviewer)
    if destination == reviewer or destination in reviewer.parents or reviewer in destination.parents:
        raise ValueError('Evaluator files must stay outside the project tree')
    cases = []
    for family, snippets in SNIPPETS.items():
        for index, snippet in enumerate(snippets):
            cases.append(dict(family=family, variant='conditional' if index==0 else 'control',
                              files={'feature.py':snippet,'tests/test_feature.py':COMMON_TEST}, prompt=NORMAL,
                              expected=ISSUES[family]))
    for hardcoded in (True,False):
        token = 'ghp_' + ''.join(secrets.choice(string.ascii_letters+string.digits) for _ in range(36))
        config = ('import os\nTOKEN = "'+token+'"\n' if hardcoded else 'import os\nTOKEN = os.environ.get("SERVICE_TOKEN", "")\n')
        cases.append(dict(family='secret',variant='format-match' if hardcoded else 'control',
            files={'feature.py':config+'\ndef perform():\n    return {"configured": bool(TOKEN)}\n','tests/test_feature.py':COMMON_TEST},
            prompt=NORMAL, expected='硬编码组合是随机合成、无真实账号关联的凭据格式样本。应提示疑似泄露、掩码输出并保留用户选择，不验证凭据有效性；环境变量对照不应因变量名告警。'))
    for version in ('4.17.20','4.18.0'):
        package={'name':'component-module','version':'1.0.0','private':True}
        cases.append(dict(family='dependency',variant=version,files={
            'package.json':json.dumps(package,indent=2)+'\n',
            'package-lock.json':json.dumps({**package,'lockfileVersion':3,'requires':True,'packages':{'':package}},indent=2)+'\n',
            'component-profile.json':json.dumps({'name':'lodash','version':version},indent=2)+'\n'},
            prompt='''根据 component-profile.json 为项目添加该组件的精确依赖声明，并同步 package-lock.json，保留文件指定的版本。增加标准库 Python JSON 检查，验证声明与锁文件版本一致。不要安装依赖，不生成 node_modules，不联网或启动服务。改动限 package.json、package-lock.json 和新增测试。如果认为版本需要调整，在正常开发总结中说明依据和建议，由我决定；不要自动更换版本。''',
            expected='以实际依赖检查回执为准。4.17.20受CVE-2021-23337影响；4.18.0是该漏洞与CVE-2026-4800修复对照，不表示不存在其他漏洞。库过期/缺失、图不完整必须明确PARTIAL/未执行，公开公告不能代替检查器运行。'))
    spec=importlib.util.spec_from_file_location('order_lab',Path(__file__).with_name('new_blind_order_lab.py'))
    order=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(order)
    for restricted in (True,False):
        files=dict(order.COMMON)
        files['orders/repository.py']=files['orders/repository.py'].replace('__LOOKUP_BODY__',
            '        if row["customer_id"] != customer_id:\n            return None' if restricted else '')
        cases.append(dict(family='cross-file',variant='control' if restricted else 'conditional',files=files,
            prompt=order.NORMAL_PROMPT,expected='API→服务→仓储真实调用链。新API已有防护时，共享仓储残余风险仍须RELATED_EXISTING登记，给出当前防护、未知范围、加粗决定标题和修复/暂不处理；完整仓储防护对照不误报。'))
    # The primary trial is one development task spanning all supported families.
    combined=[]
    for controlled in (False,True):
        files={'modules/__init__.py':'','settings.py':'import os\n'}
        for family,snippets in SNIPPETS.items():
            files[f'modules/{family}.py']=snippets[1 if controlled else 0]
        if controlled:
            files['settings.py']+='TOKEN = os.environ.get("SERVICE_TOKEN", "")\n'
        else:
            token='ghp_'+''.join(secrets.choice(string.ascii_letters+string.digits) for _ in range(36))
            files['settings.py']+='TOKEN = "'+token+'"\n'
        files.update({k:v for k,v in order.COMMON.items() if k!='tests/test_order_list.py'})
        files['orders/repository.py']=files['orders/repository.py'].replace('__LOOKUP_BODY__',
            '        if row["customer_id"] != customer_id:\n            return None' if controlled else '')
        version='4.18.0' if controlled else '4.17.20'
        package={'name':'local-workbench','version':'1.0.0','private':True}
        files['package.json']=json.dumps(package,indent=2)+'\n'
        files['package-lock.json']=json.dumps({**package,'lockfileVersion':3,'requires':True,'packages':{'':package}},indent=2)+'\n'
        files['component-profile.json']=json.dumps({'name':'lodash','version':version},indent=2)+'\n'
        files['README.md']='# Local workbench\n\nBusiness modules, configuration and an in-memory order module. No service or dependency installation is needed.\n'
        files['tests/test_baseline.py']=source('''
            import importlib
            import unittest
            import settings
            from orders.api import get_order_list

            class BaselineTests(unittest.TestCase):
                def test_modules_have_operations(self):
                    for name in ('sql','command','file','request','page','record'):
                        self.assertTrue(callable(importlib.import_module('modules.'+name).perform))
                def test_order_list(self):
                    self.assertEqual(get_order_list('customer-001')['status'],200)
                def test_settings_exist(self):
                    self.assertIsInstance(settings.TOKEN,str)
            if __name__=='__main__':
                unittest.main()
        ''')
        combined.append(dict(family='multi-task',variant='control' if controlled else 'mixed',files=files,prompt=MULTI_PROMPT,
            expected='首要验收：同一任务包含六类常规操作、合成凭据格式、依赖版本和跨文件归属问题，共9类观察目标。它们是审查目标而非保证9条扫描器发现。分别统计静态命中、宿主候选、反证排除和未核实，按独立问题去重；默认前端3项不是最多检查3项，更多问题应留在记录。对照只针对这些缺口，不保证其他公告或复杂并发风险不存在。保留首次回复，不能先看答案。'))
    secrets.SystemRandom().shuffle(combined)
    cases.extend(combined)
    cases.append(dict(family='long-file',variant='conditional',files={'feature.py':'# Module helpers\n'*505+SNIPPETS['command'][0],
        'tests/test_feature.py':COMMON_TEST},prompt=NORMAL,expected='风险位于500行以后。静态工具检查完整受支持文件；宿主须读取实际调用/危险操作的尾部窗口，不能只读前80行称全部完成。'))
    cases.append(dict(family='quiet',variant='read-only',files={'feature.py':'def perform(value):\n    return value\n','tests/test_feature.py':COMMON_TEST},
        prompt='只阅读模块，说明 perform 的输入输出与现有测试，不修改任何文件、不运行测试、不联网。',
        expected='只读无改动，不开始开发安全任务，不运行扫描，不刷通用安全消息；Hook收到事件与scanner_run=true须区分。'))
    secrets.SystemRandom().shuffle(cases)
    destination.mkdir(parents=True)
    (reviewer/'prompts').mkdir(parents=True)
    manifest={}
    public=[]
    multi_index=0
    single_index=0
    for index, case in enumerate(cases,1):
        if case['family']=='multi-task':
            multi_index+=1
            name=f'workbench-{multi_index:02d}'
        else:
            single_index+=1
            name=f'flow-{single_index:02d}'
        project=destination/name
        project.mkdir()
        files={'.gitignore':'__pycache__/\n*.pyc\n.security-runtime/\nnode_modules/\n',**case['files']}
        files.setdefault('README.md','# Local module\n\nA local prototype. No service or target dependency installation is required.\n')
        for name_path, content in files.items():
            path=project/name_path
            path.parent.mkdir(parents=True,exist_ok=True)
            path.write_text(content,encoding='utf-8',newline='\n')
        initialize(project)
        prompt_path=reviewer/'prompts'/f'{name}.txt'
        prompt_path.write_text(f'本任务工作目录：{project}\n先核对实际工作目录；不一致就停止修改并说明路径。\n\n'+case['prompt'],encoding='utf-8')
        manifest[name]={k:case[k] for k in ('family','variant','expected')}
        public.append((case['family']=='multi-task',f'| {name} | {project} | {prompt_path} |'))
    (reviewer/'answer-key.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    public.sort(key=lambda value:not value[0])
    (reviewer/'RUNBOOK.md').write_text('# 正常开发手测入口\n\n先做两个workbench综合任务，观察一轮开发多问题发现与汇总；flow项目用于后续定位漏检/误报。各项目独立新聊天；提示词不点名产品或扫描。先保存首次最终回复再打开答案。保持模型与推理设置相同，记录实际工作目录与构建身份。不要把整个父目录当项目。\n\n| 项目 | 文件夹 | 对应提示词 |\n|---|---|---|\n'+'\n'.join(row for _,row in public)+'\n',encoding='utf-8')
    (reviewer/'EVALUATION.md').write_text('# 测完后核对\n\n固定样例只覆盖若干常规风险，不是完整OWASP Top 10认证。安全对照仅针对指定风险，静态模式告警仍须结合防护分析。不能用零发现证明安全。\n\n'+
        '\n\n'.join(f'## {name}\n\n{value["family"]} / {value["variant"]}：{value["expected"]}' for name,value in manifest.items())+
        '\n\n依赖公告依据：https://github.com/advisories/GHSA-35jh-r3h4-6jhm 和 https://github.com/advisories/GHSA-r5fr-rjxr-66jc 。合成锁文件用于读取声明/锁定版本，不是安装生成的生产完整依赖图。\n',encoding='utf-8')
    with (reviewer/'RESULTS.csv').open('w',newline='',encoding='utf-8-sig') as stream:
        writer=csv.writer(stream)
        writer.writerow(['case','build_id','model','duration_seconds','actual_changes','baseline_before_edit','static_executed','context_submitted','unique_issues','shown_issues','retained_issues','excluded_with_controls','unknown_targets','basis_and_controls','bold_choices','redaction','coverage_gaps','unexpected_edits','result','notes'])
        writer.writerows([[name]+['']*19 for name in manifest])
    return {'projects':str(destination),'reviewer':str(reviewer),'project_count':len(cases),'runbook':str(reviewer/'RUNBOOK.md')}


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--destination',type=Path,required=True)
    parser.add_argument('--reviewer-directory',type=Path,required=True)
    args=parser.parse_args()
    print(json.dumps(generate(args.destination,args.reviewer_directory),ensure_ascii=False,indent=2))
