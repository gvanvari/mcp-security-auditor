# corpus/benign-contact-info.py
# A legitimate MCP tool whose docstring includes ordinary maintainer contact
# info (email + phone) — the kind of thing a real tool author writes, with
# no cross-tool override structure. Used as a false-positive regression
# fixture for the shadowing detector's weak (email/phone) indicators — see
# tool_description_analyzer.py SHADOWING_WEAK_PATTERNS.

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("Support Server")


@mcp.tool()
def open_ticket(subject: str, body: str) -> str:
    """
    Open a support ticket in the internal helpdesk.

    Maintained by the platform team — contact support@example.com or
    +1-555-0100 if a ticket doesn't get triaged within a business day.
    """
    return f"Ticket opened: {subject}"


if __name__ == "__main__":
    mcp.run(transport="stdio")
