"""CLI access to local context measurements and explicitly imported host usage."""
from __future__ import annotations

import json
from pathlib import Path


def register(subparsers):
    parser = subparsers.add_parser('context-usage', help='Read local MCP output sizes and import Codex token usage')
    actions = parser.add_subparsers(dest='context_action', required=True)
    status = actions.add_parser('status', help='Show measured calls; actual tokens require a Codex usage import')
    status.add_argument('--run', default=None)
    compare = actions.add_parser('compare', help='Compare two explicitly labelled runs')
    compare.add_argument('--baseline', required=True)
    compare.add_argument('--candidate', required=True)
    imported = actions.add_parser('import-codex', help='Import usage counters from a local Codex JSONL log, without saving its content')
    imported.add_argument('--path', type=Path, required=True)
    imported.add_argument('--run', required=True)
    for child in (status, compare, imported):
        child.add_argument('--db', type=Path, help='Explicit metrics database for an isolated experiment')
        child.add_argument('--json', action='store_true')


def execute(args):
    from .context_cost import ContextCostStore
    store = ContextCostStore(args.db)
    if args.context_action == 'import-codex':
        from .codex_usage import parse_codex_usage
        data = store.record_host_usage(args.run, parse_codex_usage(args.path))
    elif args.context_action == 'compare':
        data = store.compare(args.baseline, args.candidate)
    else:
        data = store.summary(args.run)
    # Human output also uses the stable structured report so counters and caveats
    # cannot drift between display formats.
    print(json.dumps(data, ensure_ascii=True, indent=None if args.json else 2))
    return 0 if data.get('status') in {'AVAILABLE', 'RECORDED', 'ALREADY_IMPORTED'} else 2
