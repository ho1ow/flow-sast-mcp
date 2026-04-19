"""Entry point: python -m flow_sast_mcp"""

import asyncio
from mcp.server.stdio import stdio_server
from flow_sast_mcp.server import create_server


async def _run_server():
    server = create_server()
    async with stdio_server() as (r, w):
        await server.run(r, w, server.create_initialization_options())


def main():
    asyncio.run(_run_server())


if __name__ == "__main__":
    main()
