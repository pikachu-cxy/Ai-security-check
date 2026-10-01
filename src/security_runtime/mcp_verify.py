"""Run the configured entry with the official MCP client SDK."""
from __future__ import annotations

import asyncio
import os
from pathlib import Path


REQUIRED_TOOLS = {"scan_diff", "scan_project", "get_findings", "generate_fix", "verify"}


async def _verify(entry: dict, workspace: Path, *, call_scan_diff: bool) -> tuple[bool, str]:
    from mcp import ClientSession
    from mcp.client.stdio import StdioServerParameters, stdio_client

    environment = dict(os.environ)
    environment.update(entry.get("env", {}))
    # Even an optional scan call from this verifier is Runtime self-test traffic.
    environment["SECURITY_RUNTIME_MCP_SELF_TEST"] = "1"
    parameters = StdioServerParameters(command=entry["command"], args=entry["args"],
                                      cwd=workspace, env=environment)
    async with stdio_client(parameters) as (read, write):
        async with ClientSession(read, write) as client:
            initialized = await asyncio.wait_for(client.initialize(), timeout=15)
            if initialized.serverInfo is None:
                return False, "MCP initialize did not return server information"
            listed = await asyncio.wait_for(client.list_tools(), timeout=15)
            names = {tool.name for tool in listed.tools}
            if not REQUIRED_TOOLS.issubset(names):
                return False, "MCP tool list is incomplete"
            if call_scan_diff:
                called = await asyncio.wait_for(client.call_tool("scan_diff", {}), timeout=120)
                if called.isError:
                    return False, "scan_diff returned an MCP error: " + "; ".join(
                        getattr(item, "text", type(item).__name__) for item in called.content)
    return True, "Runtime MCP initialize and tools verified"


def verify_mcp_entry(entry: dict, workspace: Path, *, call_scan_diff: bool = False) -> tuple[bool, str]:
    try:
        return asyncio.run(_verify(entry, workspace, call_scan_diff=call_scan_diff))
    except Exception as exc:
        return False, f"MCP verification failed: {type(exc).__name__}"
