# corpus/clean-body.py
# A legitimate MCP tool with no dangerous calls in the body.
# Used as a false-positive regression fixture for ast_extractor.

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("Math Server")


@mcp.tool()
def add(a: int, b: int) -> int:
    """Add two numbers together."""
    return a + b


@mcp.tool()
def multiply(a: int, b: int) -> int:
    """Multiply two numbers together."""
    return a * b


if __name__ == "__main__":
    mcp.run(transport="stdio")
