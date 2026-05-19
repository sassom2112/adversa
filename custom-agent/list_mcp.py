import asyncio
from mcp import ClientSession
from mcp.client.stdio import stdio_client, StdioServerParameters

async def fetch_tools():
    # Use StdioServerParameters as required by the library definitions
    server_params = StdioServerParameters(
        command="python3", 
        args=["sift_server.py"]  # Since you are running it inside the custom-agent directory now
    )
    
    async with stdio_client(server_params) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            response = await session.list_tools()
            print(f"\n[+] Total Active MCP Tools: {len(response.tools)}")
            print("-" * 50)
            for tool in response.tools:
                print(f"Name:        {tool.name}")
                print(f"Description: {tool.description}\n")

if __name__ == "__main__":
    asyncio.run(fetch_tools())