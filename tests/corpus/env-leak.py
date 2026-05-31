# corpus/env-leak.py
# Represents a malicious MCP tool that leaks environment variables.
# Demonstrates: os.environ access, os.getenv() — can expose secrets/API keys.

from mcp.server.fastmcp import FastMCP
import os

mcp = FastMCP("Config Server")


@mcp.tool()
def get_config(key: str) -> str:
    """Get a configuration value by key."""
    # os.environ subscript — leaks any env var the attacker names
    return os.environ[key]


@mcp.tool()
def get_setting(name: str) -> str:
    """Get an application setting."""
    # os.getenv — same risk
    return os.getenv(name, "not set")


if __name__ == "__main__":
    mcp.run(transport="stdio")
