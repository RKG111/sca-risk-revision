"""
Module 4 — Agent Tool: AST Slicer

Extracts relevant code slices around a specific function or symbol
using Tree-sitter. This gives the agent focused context without
loading entire files.
"""

import logging
from pathlib import Path

from langchain_core.tools import tool

logger = logging.getLogger(__name__)

_codebase_root: Path = Path("/codebases")


def set_codebase_root(path: Path):
    global _codebase_root
    _codebase_root = path


@tool
def get_function_body(relative_path: str, function_name: str) -> str:
    """
    Extracts the complete source code of a specific function from a Python file.
    Returns the function signature and body as a string.

    Use this to inspect a function's logic in detail after identifying it as suspicious.

    Args:
        relative_path: File path relative to codebase root
        function_name: Exact name of the function to extract
    """
    target = _codebase_root / relative_path
    if not target.exists():
        return f"File not found: {relative_path}"

    try:
        import tree_sitter_python as tspython
        from tree_sitter import Language, Parser

        language = Language(tspython.language())
        parser = Parser(language)
        source = target.read_bytes()
        tree = parser.parse(source)
        source_str = source.decode("utf-8", errors="replace")

        for node in _walk(tree.root_node):
            if node.type in ("function_definition", "async_function_definition"):
                name_node = node.child_by_field_name("name")
                if name_node and source_str[name_node.start_byte:name_node.end_byte] == function_name:
                    body = source_str[node.start_byte:node.end_byte]
                    return f"# {relative_path} — {function_name}\n{body}"

        return f"Function '{function_name}' not found in {relative_path}"

    except ImportError:
        # Fallback: simple line-based extraction
        lines = target.read_text(encoding="utf-8", errors="replace").splitlines()
        result = []
        in_func = False
        for i, line in enumerate(lines, 1):
            if f"def {function_name}" in line or f"async def {function_name}" in line:
                in_func = True
            if in_func:
                result.append(f"{i:4d} | {line}")
                if len(result) > 1 and line.strip() == "" and not lines[i - 1].startswith(" "):
                    break
        return "\n".join(result) if result else f"Function '{function_name}' not found"


@tool
def list_functions_in_file(relative_path: str) -> str:
    """
    Lists all function and method definitions in a Python file.
    Returns function names with their line numbers.

    Use this to understand the structure of a file before diving into specific functions.

    Args:
        relative_path: File path relative to codebase root
    """
    target = _codebase_root / relative_path
    if not target.exists():
        return f"File not found: {relative_path}"

    try:
        import tree_sitter_python as tspython
        from tree_sitter import Language, Parser

        language = Language(tspython.language())
        parser = Parser(language)
        source = target.read_bytes()
        tree = parser.parse(source)
        source_str = source.decode("utf-8", errors="replace")

        funcs = []
        for node in _walk(tree.root_node):
            if node.type in ("function_definition", "async_function_definition"):
                name_node = node.child_by_field_name("name")
                if name_node:
                    name = source_str[name_node.start_byte:name_node.end_byte]
                    line = node.start_point[0] + 1
                    funcs.append(f"  line {line:4d}: {name}")

        if not funcs:
            return f"No functions found in {relative_path}"
        return f"{relative_path}:\n" + "\n".join(funcs)

    except ImportError:
        lines = target.read_text(encoding="utf-8", errors="replace").splitlines()
        funcs = [
            f"  line {i + 1:4d}: {line.strip().split('(')[0].replace('def ', '').replace('async def ', '')}"
            for i, line in enumerate(lines)
            if line.strip().startswith(("def ", "async def "))
        ]
        return f"{relative_path}:\n" + "\n".join(funcs) if funcs else "No functions found"


def _walk(node):
    yield node
    for child in node.children:
        yield from _walk(child)
