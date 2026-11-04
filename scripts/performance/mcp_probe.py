"""Read-only MCP client timing; no workspace admission, scan or model call."""
import argparse
import asyncio
import json
import os
from pathlib import Path
import statistics
import time
from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client


async def probe(command, samples):
    started = time.perf_counter()
    async with stdio_client(StdioServerParameters(command=command[0], args=command[1:], env=dict(os.environ))) as (read, write):
        async with ClientSession(read, write) as client:
            await client.initialize()
            initialization_ms = (time.perf_counter()-started)*1000
            started = time.perf_counter()
            listing = await client.list_tools()
            discovery_ms = (time.perf_counter()-started)*1000
            rows = []
            for index in range(samples):
                started = time.perf_counter()
                result = await client.call_tool('get_runtime_info', {'view': 'summary'})
                duration = (time.perf_counter()-started)*1000
                # Measure the serialized result, never retain its content.
                rows.append(dict(sample=index+1, roundtrip_ms=round(duration,3),
                    serialized_result_bytes=len(result.model_dump_json().encode()), is_error=bool(result.isError)))
            return dict(contract='mcp-performance-probe-v1', initialization_ms=initialization_ms,
                discovery_ms=discovery_ms, tools=len(listing.tools), listing_paginated=bool(listing.nextCursor),
                listed_page_bytes=len(listing.model_dump_json().encode()), samples=rows,
                median_ms=statistics.median(r['roundtrip_ms'] for r in rows),
                host_model_ms=None, client='DIRECT_STDIO_NOT_DESKTOP')


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--samples', type=int, default=20)
    parser.add_argument('command', nargs=argparse.REMAINDER)
    args=parser.parse_args()
    command=args.command[1:] if args.command[:1]==['--'] else args.command
    if not command or not 1 <= args.samples <= 100:
        parser.error('Command and 1..100 samples required')
    result=asyncio.run(asyncio.wait_for(probe(command,args.samples),timeout=300))
    destination=os.environ.get('SECURITY_RUNTIME_PERF_DIR')
    if destination:
        # Runner creates this private directory; exclusive creation prevents replacement.
        with (Path(destination)/'mcp-client.json').open('x') as stream:
            json.dump(result,stream,indent=2)
    print(json.dumps(result,indent=2))


if __name__=='__main__':
    main()
