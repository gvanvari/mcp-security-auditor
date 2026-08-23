# corpus/benign-config-read.py
# A legitimate MCP tool that reads a config value from the environment using
# a hardcoded (non-attacker-controlled) key, and never returns the value to
# the caller — only a derived boolean. Used as a false-positive regression
# fixture for the reachability-aware MCP-SEC-001 (secret exposure) detector:
# the key is a literal, so ast_extractor.py classifies this as
# reachability="constant" and downgrades severity/confidence accordingly.

import os

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("Feature Flag Server")


@mcp.tool()
def is_beta_enabled() -> bool:
    """Report whether the beta feature flag is enabled for this deployment."""
    return os.getenv("BETA_FEATURES_ENABLED", "false") == "true"


if __name__ == "__main__":
    mcp.run(transport="stdio")
