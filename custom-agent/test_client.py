import asyncio
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

async def main():
    server_params = StdioServerParameters(
        command="python3",
        args=["sift_server.py"]
    )
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            # In test_client.py, change the command to:
            result = await session.call_tool("run_terminal_command", {"command": "/usr/local/bin/vol --help"})
            print(result.content[0].text)

asyncio.run(main())
