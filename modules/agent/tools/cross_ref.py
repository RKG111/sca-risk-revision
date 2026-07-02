"""
Module 4 — Agent Tool: Cross-Reference Tracer

Finds where functions/symbols are defined, called, or referenced
across the codebase. Gives the agent call-graph awareness without
requiring a full CPG.
"""

import logging
from pathlib import Path

from langchain_core.tools import tool

logger = logging.getLogger(__name__)

_codebase_root: Path = Path("/codebases")
_code_index = None


def set_codebase_root(path: Path):
    global _codebase_root
    _codebase_root = path


def set_code_index(index):
    global _code_index
    _code_index = index


@tool
def find_all_callers(function_name: str) -> str:
    """
    Finds all locations in the codebase that call a specific function or method.
    Returns file path, line number, and the surrounding line.

    Use this to trace who calls a suspicious function and whether
    untrusted input can reach it.

    Args:
        function_name: The function/method name to search for (e.g. 'deserialize', 'load')
    """
    matches = []
    pattern = f"{function_name}("
    for path in _codebase_root.glob("**/*.py"):
        try:
            for i, line in enumerate(
                path.read_text(encoding="utf-8", errors="replace").splitlines(), start=1
            ):
                if pattern in line:
                    rel = path.relative_to(_codebase_root)
                    matches.append(f"{rel}:{i}: {line.strip()}")
        except OSError:
            continue

    if not matches:
        return f"No callers of '{function_name}' found."
    return f"Callers of '{function_name}':\n" + "\n".join(matches[:30])


@tool
def find_definition(symbol_name: str) -> str:
    """
    Finds where a function, class, or variable is defined in the codebase.

    Args:
        symbol_name: The symbol name to locate (e.g. 'UserDeserializer', 'validate_input')
    """
    if _code_index:
        locations = _code_index.find_function(symbol_name)
        if locations:
            return "\n".join(
                f"{loc['file']}:{loc['line']} — {symbol_name}({', '.join(loc['params'])})"
                for loc in locations
            )

    matches = []
    for path in _codebase_root.glob("**/*.py"):
        try:
            for i, line in enumerate(
                path.read_text(encoding="utf-8", errors="replace").splitlines(), start=1
            ):
                stripped = line.strip()
                if stripped.startswith(f"def {symbol_name}") or stripped.startswith(f"class {symbol_name}"):
                    rel = path.relative_to(_codebase_root)
                    matches.append(f"{rel}:{i}: {stripped[:80]}")
        except OSError:
            continue

    if not matches:
        return f"Definition of '{symbol_name}' not found."
    return "\n".join(matches)


@tool
def get_import_chain(module_name: str) -> str:
    """
    Shows which files import a given module and what symbols they pull from it.
    Useful for understanding the blast radius of a vulnerable dependency.

    Args:
        module_name: The module to trace (e.g. 'yaml', 'pickle', 'subprocess')
    """
    if _code_index:
        files = _code_index.files_importing(module_name)
        if files:
            return f"Files importing '{module_name}':\n" + "\n".join(f"  {f}" for f in files)
        return f"No files import '{module_name}'"

    matches = []
    for path in _codebase_root.glob("**/*.py"):
        try:
            for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
                stripped = line.strip()
                if f"import {module_name}" in stripped or f"from {module_name}" in stripped:
                    rel = path.relative_to(_codebase_root)
                    matches.append(f"  {rel}: {stripped}")
                    break
        except OSError:
            continue

    if not matches:
        return f"No files import '{module_name}'"
    return f"Files importing '{module_name}':\n" + "\n".join(matches)
