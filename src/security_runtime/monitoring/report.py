"""Downloadable metadata-only trial bundle, including an offline HTML view."""
from html import escape
from io import BytesIO
import json
from zipfile import ZipFile, ZIP_DEFLATED


def report_bundle(report):
    data = json.dumps(report, ensure_ascii=False, indent=2)
    trial = report['trial']
    usage = trial['usage']
    def display(value):
        return '未知' if value is None else escape(str(value))
    rows = [('本窗口总 token', usage['total_tokens'] if usage else None),
            ('输入 token', usage['input_tokens'] if usage else None),
            ('缓存输入（包含在输入中）', usage['cached_input_tokens'] if usage else None),
            ('输出 token', usage['output_tokens'] if usage else None),
            ('窗口总时长（毫秒）', trial['window_elapsed_ms']),
            ('已关联工具累计耗时（毫秒）', trial['elapsed_ms']),
            ('已关联工具区间并集（毫秒）', trial['timing']['tool_active_wall_ms']),
            ('已关联工具调用数', trial['calls']),
            ('未关联聊天的项目调用数', trial['unassociated_chat_calls']),
            ('用量更新时间（Unix 秒）', trial['host']['as_of']),
            ('起始用量是否缺失', trial['window_token_prefix_unmeasured']),
            ('开发专属 token / 安全专属 token', None)]
    table = ''.join('<tr><th>'+escape(name)+'</th><td>'+display(value)+'</td></tr>' for name, value in rows)
    notes = ''.join('<li>'+escape(item)+'</li>' for item in report['measurement_notes'])
    html = ('<!doctype html><html lang="zh-CN"><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        '<title>试用消耗报告</title><style>body{font:16px system-ui;max-width:980px;margin:40px auto;padding:20px;color:#172b42}'
        'table{border-collapse:collapse;width:100%}th,td{text-align:left;padding:12px;border-bottom:1px solid #ddd}'
        'li{margin:12px 0}pre{white-space:pre-wrap;overflow-wrap:anywhere}</style>'
        '<h1>试用消耗报告</h1><p>数据状态：'+escape(trial['status'])+'</p><table>'+table+
        '</table><ul>'+notes+'</ul><details><summary>查看完整脱敏统计</summary><pre>'+escape(data)+'</pre></details></html>')
    output = BytesIO()
    with ZipFile(output, 'w', ZIP_DEFLATED) as archive:
        archive.writestr('usage-report.json', data)
        archive.writestr('usage-report.html', html)
        archive.writestr('README.txt', '\n'.join(report['measurement_notes']))
    return output.getvalue()
