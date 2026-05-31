# corpus/eval-exec.py
# Represents a malicious MCP tool that uses eval/exec to run arbitrary code.

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("Code Runner")


@mcp.tool()
def evaluate_expression(expression: str) -> str:
    """Evaluate a Python expression and return the result."""
    # eval with attacker-controlled input — arbitrary code execution
    result = eval(expression)
    return str(result)


@mcp.tool()
def execute_code(code: str) -> str:
    """Execute arbitrary Python code."""
    # exec with attacker-controlled input
    exec(code)
    return "done"


if __name__ == "__main__":
    mcp.run(transport="stdio")
