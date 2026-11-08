"""Chinese dashboard projections; never alter findings, decisions or evidence."""
import hashlib
import json
import re
from functools import lru_cache
from .redactor import SecretRedactor

VERSION = 'zh-risk-presentation-v1'
# Templates describe possibilities, not proof of exploitability.
TEMPLATES = {
 'sql-injection': ('SQL 注入风险', '外部输入可能参与 SQL 查询拼接，需核对是否缺少参数化绑定。', '如果攻击者能控制这些输入，可能绕过查询限制读取或修改数据；范围取决于查询和数据库权限。', '使用参数化查询，将数据与 SQL 语句结构分离。'),
 'command-injection': ('命令注入风险', '不可信输入可能进入系统命令执行，需核对参数传递和输入限制。', '如果输入可被攻击者控制，可能执行程序原本不允许的系统操作。', '优先使用专用 API；必须执行命令时使用固定程序和独立参数，并限制参数取值。'),
 'path-traversal': ('文件路径越界风险', '外部输入可能影响文件路径，需核对规范化后的路径是否被限制在授权目录。', '攻击者可能访问原本不允许读取或修改的文件，具体影响取决于文件操作和程序权限。', '规范化路径后验证目录边界，并处理符号链接与访问权限。'),
 'xss': ('跨站脚本风险', '不可信内容可能进入网页输出，需核对输出上下文的编码或净化。', '用户打开相关页面时，恶意内容可能借用用户身份执行操作或读取页面数据。', '按 HTML、属性、URL 或脚本上下文正确编码；避免直接插入不可信 HTML。'),
 'secret': ('疑似凭据暴露', '记录包含符合凭据规则的内容，格式命中不能证明凭据真实或仍然有效。', '如果是真实且有效的凭据，获得代码的人可能访问该凭据权限范围内的服务或数据。', '核实凭据用途和有效性；若确认暴露，撤销或轮换凭据，并使用安全的凭据存储。'),
 'dependency': ('依赖漏洞风险', '依赖版本命中漏洞公告；是否可利用仍取决于受影响功能、版本范围和调用条件。', '如果项目使用了公告涉及的功能，可能受到该漏洞影响；仅凭版本命中不能确定具体业务损失。', '核对漏洞公告、受影响版本及修复版本，升级依赖并验证兼容性。'),
 'configuration': ('安全配置风险', '记录指出安全防护配置可能缺失或弱化，需结合配置实际生效范围核对。', '如果该配置在实际环境生效，可能降低访问或数据保护；具体后果取决于配置用途。', '根据规则说明恢复所需防护，并验证实际部署配置。'),
 'tls': ('通信验证风险', '通信连接可能未正确验证证书或服务器身份，需核对实际连接配置。', '连接被劫持时，对方可能冒充服务器读取或篡改通信内容。', '启用证书链和主机名校验，使用受信任的证书配置。'),
 'business-logic': ('业务逻辑风险', '业务流程可能缺少必要约束或状态校验，需结合实际操作顺序和业务规则核对。', '如果该流程可被绕过，可能产生不符合业务规则的操作或损失；具体后果以审计证据为准。', '在服务端落实业务约束，并验证异常顺序、重复操作和边界条件。'),
 'authorization': ('访问控制风险', '业务操作可能缺少身份、资源归属或权限校验，需结合实际流程核对。', '如果校验可被绕过，用户可能查看他人的数据或执行无权执行的操作。', '在服务端验证每次操作的身份、资源归属和权限，默认拒绝未授权访问。'),
}
RULE_CATEGORIES = {'ai-security.java.trust-all-hostname':'tls', 'ai-security.java.trust-all-certificates':'tls'}
ALIASES = {'sql':'sql-injection', 'sqli':'sql-injection', 'secrets':'secret', 'path':'path-traversal', 'command':'command-injection', 'business-logic':'business-logic'}
FALLBACK = ('潜在安全风险', '扫描或审计记录报告此位置存在潜在风险，当前尚无对应的中文规则解释。', '具体影响尚未确认，请结合原始说明、调用路径和访问权限核对。', '结合原始规则和代码证据确定修复措施；当前暂无专门的中文修复说明。')


def chinese(value):
    """A Chinese sentence, not an English description containing a Chinese path."""
    return isinstance(value, str) and len(re.findall(r'[\u4e00-\u9fff]', value)) >= 4


def normalized(value):
    return re.sub(r'[\W_]+', '', str(value)).casefold()


def section(report, label):
    match = re.search(r'\*\*'+label+r'\*\*\s*[：:]?\s*([\s\S]*?)(?=\n\s*\*\*|$)', report)
    return match.group(1).strip() if match else ''


@lru_cache(maxsize=2048)
def _render(payload):
    row = json.loads(payload)
    report = row.get('report_text') or ''
    category = RULE_CATEGORIES.get(row.get('rule_id'), ALIASES.get(row.get('category'), row.get('category')))
    template = TEMPLATES.get(category, FALLBACK)
    heading = re.match(r'^\*\*([^*]+)\*\*', report)
    title = heading[1] if heading and chinese(heading[1]) else row.get('title', '')
    result = dict(title_zh=title if chinese(title) else template[0])
    sources = {}
    fields = [('technical_explanation_zh','问题','description',1), ('plain_impact_zh','可能影响','impact',2), ('advice_zh','建议修复','advice',3), ('unknowns_zh','尚未确认','unknowns',None)]
    for key,label,raw,index in fields:
        candidate = section(report, label)
        source = 'REVIEW_REPORT'
        if not chinese(candidate):
            candidate,source = row.get(raw,''),'SAVED_CONTENT'
        duplicate = key == 'plain_impact_zh' and normalized(candidate) in {
            normalized(result.get('technical_explanation_zh','')), normalized(row.get('description','')), normalized(section(report,'问题'))}
        if not chinese(candidate) or duplicate or candidate in {'具体影响尚未确认。', '未记录'}:
            candidate = template[index] if index is not None else '实际可达性、外部防护和当前源码状态尚需结合原始记录确认。'
            source = 'CATEGORY_TEMPLATE' if category in TEMPLATES else 'CONSERVATIVE_FALLBACK'
        result[key] = candidate
        sources[key] = source
    result.update(content_source=sources, presentation_version=VERSION,
                  source_revision=hashlib.sha256(payload.encode()).hexdigest())
    return result


def present(row):
    # Only bounded display text enters the cache. Return a fresh object per reader.
    redact = SecretRedactor().redact
    display = dict(row)
    content = row.get('report_content') or {}
    if content:
        display['report_text'] = ''
        for name, target in [('title','title'),('problem','description'),('impact','impact'),('advice','advice'),('unknowns','unknowns')]:
            if content.get(name):
                display[target] = content[name]
    keys = ('title','description','impact','advice','unknowns','report_text','category','rule_id')
    payload = json.dumps({k:redact(str(display.get(k) or ''))[:20000 if k=='report_text' else 4000] for k in keys}, sort_keys=True)
    return dict(row, presentation=json.loads(json.dumps(_render(payload), ensure_ascii=False)))
