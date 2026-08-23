"""
EntryPointExtractor — P2-7 code-KB bridge.

Walks a file's AST to list its @mcp.tool() functions as entry points
(name, parameters, line range). Used by AttackSurfaceReporter to attribute
ThreatVector findings (already located by "file:line") back to the tool
that reaches them, reusing the P1-1 reachability verdict rather than
re-deriving it.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import List

from pydantic import BaseModel


class ToolEntryPoint(BaseModel):
    """One @mcp.tool() function: its identity, parameters, and line range."""

    name: str
    params: List[str]
    lineno: int
    end_lineno: int

    def contains_line(self, line: int) -> bool:
        return self.lineno <= line <= self.end_lineno


def _is_mcp_tool_func(node: "ast.FunctionDef | ast.AsyncFunctionDef") -> bool:
    """Return True if function is decorated with @mcp.tool() or @server.tool()."""
    for dec in node.decorator_list:
        if isinstance(dec, ast.Call):
            func = dec.func
            if isinstance(func, ast.Attribute) and func.attr == "tool":
                return True
        elif isinstance(dec, ast.Attribute) and dec.attr == "tool":
            return True
    return False


class EntryPointExtractor:
    """Lists @mcp.tool() functions in a file as ToolEntryPoints."""

    def extract(self, file_path: str) -> List[ToolEntryPoint]:
        source = Path(file_path).read_text(encoding="utf-8")
        try:
            tree = ast.parse(source, filename=file_path)
        except SyntaxError:
            return []

        entry_points: List[ToolEntryPoint] = []
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if not _is_mcp_tool_func(node):
                continue
            entry_points.append(ToolEntryPoint(
                name=node.name,
                params=[arg.arg for arg in node.args.args],
                lineno=node.lineno,
                # end_lineno is guaranteed on parsed nodes (Python 3.8+); fall
                # back to lineno for the pathological single-line-body case.
                end_lineno=node.end_lineno or node.lineno,
            ))

        return entry_points
