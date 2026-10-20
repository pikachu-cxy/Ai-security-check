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
    monitor = actions.add_parser('monitor', help='Switch collection live: off, basic, or debug; retain historical data')
    monitor.add_argument('--mode', choices=('off', 'basic', 'debug'))
    monitor.add_argument('--run', help='Label subsequent calls without restarting the MCP process')
    report = actions.add_parser('report', help='Export a private offline HTML or JSON snapshot of real retained measurements')
    report.add_argument('--run', default=None)
    report.add_argument('--output', type=Path, required=True, help='New .html or .json file; existing files are never overwritten')
    report.add_argument('--limit', type=int, default=2000, help='Maximum call details, 1–10000; totals cover all retained records')
    dashboard = actions.add_parser('dashboard', help='Run the optional loopback-only live monitor; Ctrl+C stops it without stopping Runtime')
    dashboard.add_argument('--project', type=Path, help='Explicit project selector; never a scan target')
    dashboard.add_argument('--chat-log', type=Path, help='Explicit current chat usage log; no directory discovery')
    dashboard.add_argument('--port', type=int, default=0, help='Local port; 0 selects a free port')
    for child in (status, compare, imported, monitor, report, dashboard):
        child.add_argument('--db', type=Path, help='Explicit metrics database for an isolated experiment')
        child.add_argument('--json', action='store_true')


def execute(args):
    from .context_cost import ContextCostStore
    store = ContextCostStore(args.db)
    if args.context_action == 'dashboard':
        from .monitoring.server import serve
        serve(store, project=args.project, chat_log=args.chat_log, port=args.port)
        return 0
    if args.context_action == 'monitor':
        data = store.set_monitoring(args.mode, args.run) if args.mode is not None else store.monitoring()
    elif args.context_action == 'report':
        from .context_report import report_data, write_report
        try:
            report = report_data(store, args.run, limit=args.limit)
            write_report(args.output, report)
            data = dict(status=report['status'], output=str(args.output.absolute()),
                        calls=report['summary']['calls'], omitted_events=report['omitted_events'])
        except (OSError, ValueError, TypeError, KeyError):
            data = dict(status='UNAVAILABLE', reason_code='CONTEXT_REPORT_EXPORT_FAILED',
                        hint='Use valid measurements, a limit of 1–10000, and a new .html/.json file in an existing directory.')
    elif args.context_action == 'import-codex':
        from .codex_usage import parse_codex_usage
        data = store.record_host_usage(args.run, parse_codex_usage(args.path))
    elif args.context_action == 'compare':
        data = store.compare(args.baseline, args.candidate)
    else:
        data = store.summary(args.run)
    # Human output also uses the stable structured report so counters and caveats
    # cannot drift between display formats.
    print(json.dumps(data, ensure_ascii=True, indent=None if args.json else 2))
    return 0 if data.get('status') in {'AVAILABLE', 'PARTIAL', 'RECORDED', 'ALREADY_IMPORTED'} else 2
