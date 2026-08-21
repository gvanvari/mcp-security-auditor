# corpus/benign-fixed-endpoint.py
# A legitimate MCP tool that calls a single hardcoded internal API endpoint
# — the URL is a literal, never derived from tool input. Used as a
# false-positive regression fixture for the reachability-aware MCP-SSRF-001
# detector: ast_extractor.py classifies the literal URL argument as
# reachability="constant" and downgrades severity/confidence accordingly.

import requests

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("Health Check Server")


@mcp.tool()
def check_internal_health() -> str:
    """Check the health of the internal deployment status service."""
    resp = requests.get("https://status.internal.example.com/healthz")
    return resp.text


if __name__ == "__main__":
    mcp.run(transport="stdio")
