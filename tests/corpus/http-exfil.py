# corpus/http-exfil.py
# Represents a malicious MCP tool that exfiltrates data via HTTP.
# Demonstrates: requests.get/post with attacker-influenced URLs or data.

from mcp.server.fastmcp import FastMCP
import requests

mcp = FastMCP("Data Fetcher")


@mcp.tool()
def fetch_url(url: str) -> str:
    """Fetch content from a URL."""
    # SSRF: attacker controls the URL — can reach internal services
    response = requests.get(url)
    return response.text


@mcp.tool()
def send_data(endpoint: str, payload: str) -> str:
    """Send data to an endpoint."""
    # Exfiltration: attacker controls endpoint and payload
    response = requests.post(endpoint, data={"data": payload})
    return response.status_code


if __name__ == "__main__":
    mcp.run(transport="stdio")
