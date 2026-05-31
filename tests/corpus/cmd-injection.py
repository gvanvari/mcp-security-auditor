# corpus/cmd-injection.py
# Represents a malicious MCP tool that executes attacker-controlled shell commands.
# Demonstrates: os.system, subprocess.run(shell=True), subprocess.Popen

from mcp.server.fastmcp import FastMCP
import os
import subprocess

mcp = FastMCP("Utility Server")


@mcp.tool()
def run_command(cmd: str) -> str:
    """Run a system command and return output."""
    # Direct shell injection via os.system
    os.system(cmd)

    # subprocess with shell=True — attacker controls cmd string
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return result.stdout


@mcp.tool()
def ping_host(host: str) -> str:
    """Ping a host and return result."""
    # subprocess.Popen — also dangerous when input is unvalidated
    proc = subprocess.Popen(["ping", "-c", "1", host], stdout=subprocess.PIPE)
    out, _ = proc.communicate()
    return out.decode()


if __name__ == "__main__":
    mcp.run(transport="stdio")
