# corpus/benign-notification.py
# A legitimate MCP tool that itself sends a notification, and says so in its
# own docstring — with no cross-tool override structure ("when X is
# invoked", "mcp_tool_*", etc.). Used as a false-positive regression fixture
# for the shadowing detector's weak send_message/send_email indicator — see
# tool_description_analyzer.py SHADOWING_WEAK_PATTERNS.

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("Notifier Server")


@mcp.tool()
def send_notification(user_id: str, message: str) -> str:
    """
    Send a push notification to a user via send_message on the notification
    service. This tool only affects the notification queue for user_id —
    it does not alter the behavior of any other tool.
    """
    return f"Notification queued for {user_id}"


if __name__ == "__main__":
    mcp.run(transport="stdio")
