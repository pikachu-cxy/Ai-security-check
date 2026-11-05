"""Build current-source knowledge indexes without importing or executing Runtime."""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / 'src/security_runtime'
OUTPUT = ROOT / 'docs/knowledge'


def symbols(body, prefix=''):
    result = []
    for node in body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            name = prefix + node.name
            result.append({'name': name, 'line': node.lineno})
            if isinstance(node, ast.ClassDef):
                result.extend(symbols(node.body, name + '.'))
    return result


def collect():
    modules, tools = [], []
    group_tree = ast.parse((SOURCE / 'mcp_tool_groups.py').read_text(encoding='utf-8'))
    groups = next(ast.literal_eval(node.value) for node in group_tree.body
                  if isinstance(node, ast.Assign)
                  and any(isinstance(t, ast.Name) and t.id == 'GROUPS' for t in node.targets))
    routes = {name: group for group, names in groups.items() for name in names}
    for path in sorted(SOURCE.rglob('*.py')):
        if any(part in {'rules', '__pycache__'} for part in path.relative_to(SOURCE).parts):
            continue
        source_bytes = path.read_bytes()
        tree = ast.parse(source_bytes.decode('utf-8-sig'), filename=str(path))
        relative = path.relative_to(ROOT).as_posix()
        doc = ast.get_docstring(tree) or ''
        modules.append({'path': relative, 'sha256': hashlib.sha256(source_bytes).hexdigest(),
                        'purpose': doc.split('\n')[0], 'symbols': symbols(tree.body)})
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            decorators = [d for d in node.decorator_list if isinstance(d, ast.Call)
                          and isinstance(d.func, ast.Attribute) and d.func.attr == 'tool']
            if not decorators:
                continue
            tools.append({'name': node.name, 'group': routes.get(node.name, '直接声明或条件开放'),
                          'path': relative, 'line': node.lineno,
                          'signature': f'{node.name}({ast.unparse(node.args)})',
                          'description': (ast.get_docstring(node) or '').replace('\n', ' ')})
    missing = sorted(set(routes) - {tool['name'] for tool in tools})
    if missing:
        raise ValueError('Grouped operations lack static tool declarations: ' + ', '.join(missing))
    return modules, sorted(tools, key=lambda tool: (tool['group'], tool['name'], tool['path']))


def render(modules, tools):
    lines = ['# MCP 对外入口与内部操作索引', '',
             '由 `scripts/maintenance/knowledge_index.py` 从当前源码静态生成，请勿手改。', '',
             '## 对外工具入口（Codex 全局模式）', '',
             '正常注册成功时，当前发现契约为 19 个入口；启用 `start_usage_monitor` 时为 20 个。',
             '其中 12 个是分组入口，7 个是独立入口。WorkBuddy 隐藏 Hook；Cursor 不使用该分组发现，不能套用此数量。',
             '依据：[全局注册](../../src/security_runtime/global_mcp.py)、[发现契约测试](../../tests/test_mcp_tool_groups.py)。', '',
             '独立入口：`get_runtime_info`、`get_runtime_guidance`、`handle_before_hook_event`、`handle_hook_event`、`handle_readiness_event`、`handle_stop_event`、`start_risk_dashboard`。', '',
             '该计数依据当前注册逻辑与契约测试，静态生成器不执行服务发现。监控注册异常可使实际列表减少，连接的 `tools/list` 是最终依据。',
             '分组入口使用 `operation/arguments`；独立入口直接传参数。兼容旧操作调用不表示该操作仍独立出现在发现列表。', '',
             '| 对外分组工具 | arguments 对应的内部 operation |',
             '| --- | --- |']
    for group in sorted({tool['group'] for tool in tools} - {'直接声明或条件开放'}):
        names = sorted({tool['name'] for tool in tools if tool['group'] == group})
        lines.append(f"| `{group}` | " + '、'.join(f'`{name}`' for name in names) + ' |')
    lines.extend(['', '## 内部声明定位', '',
             '以下统计 `@*.tool(...)` 的源码声明，含分组成员、条件接口及包装声明，不能相加作为对外工具数量。',
             '签名是原声明，最终工作区必填字段、嵌套模型约束及分组 schema 见实际连接与 [接口设计](INTERFACES.md)。', '',
             f'当前收录 {len(tools)} 处底层声明位置。源码中的条件注册与包装不在此执行。', ''])
    for tool in tools:
        lines.extend([f"### {tool['group']} / {tool['name']}", '',
                      f"定义：[{tool['path']}:{tool['line']}](../../{tool['path']}#L{tool['line']})", '',
                      '```python', tool['signature'], '```', '', tool['description'], ''])
    return {'MCP_CATALOG.md': '\n'.join(lines),
            'SYMBOLS.json': json.dumps({'scope': 'current src/security_runtime Python source',
                                       'modules': modules}, ensure_ascii=False, indent=2) + '\n'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--check', action='store_true', help='Read-only comparison; nonzero if indexes are stale')
    mode.add_argument('--find', help='Read-only case-insensitive symbol/path/purpose lookup')
    args = parser.parse_args()
    modules, tools = collect()
    if args.find is not None:
        needle = args.find.casefold()
        for module in modules:
            module_match = needle in (module['path'] + ' ' + module['purpose']).casefold()
            matches = [s for s in module['symbols'] if needle in s['name'].casefold()]
            if module_match or matches:
                print(module['path'] + ': ' + module['purpose'])
                for symbol in matches:
                    print(f"  {symbol['line']}: {symbol['name']}")
        for tool in tools:
            if needle in (tool['name'] + ' ' + tool['group']).casefold():
                print(f"{tool['path']}:{tool['line']}: {tool['group']}/{tool['name']}")
        return 0
    stale = []
    for name, content in render(modules, tools).items():
        path = OUTPUT / name
        if args.check:
            if not path.is_file() or path.read_text(encoding='utf-8') != content:
                stale.append(name)
        else:
            OUTPUT.mkdir(parents=True, exist_ok=True)
            # Avoid generating file-watch events for unchanged indexes.
            if not path.is_file() or path.read_bytes() != content.encode('utf-8'):
                path.write_text(content, encoding='utf-8', newline='\n')
    if stale:
        print('Stale knowledge indexes: ' + ', '.join(stale))
        return 1
    print(f"Knowledge indexes {'checked' if args.check else 'generated'}: {len(modules)} modules, {len(tools)} tool declarations")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
