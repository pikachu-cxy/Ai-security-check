"""Standalone entry point, independent of MCP and product lifecycle."""
import argparse
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description='Optional local consumption monitor')
    parser.add_argument('--db', type=Path)
    parser.add_argument('--project', type=Path)
    parser.add_argument('--chat-log', type=Path)
    parser.add_argument('--port', type=int, default=0)
    args = parser.parse_args()
    from ..context_cost import ContextCostStore
    from .server import serve
    serve(ContextCostStore(args.db), project=args.project, chat_log=args.chat_log, port=args.port)


if __name__ == '__main__':
    main()
