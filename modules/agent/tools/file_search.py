"""
Module 4 — Agent Tool: File Search

Allows the LangGraph agent to search for files by name or content pattern.
Returns structured results the agent can reason over.
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
def search_files_by_name(pattern: str) -> str:
    """
    Search for files in the codebase whose names match the given glob pattern.
    Returns a newline-separated list of relative file paths.

    Examples:
        search_files_by_name("*.py")
        search_files_by_name("auth*.py")
        search_files_by_name("*serializer*")
    """
    matches = sorted(_codebase_root.glob(f"**/{pattern}"))
    if not matches:
        return f"No files matching '{pattern}' found."
    return "\n".join(str(p.relative_to(_codebase_root)) for p in matches[:50])


@tool
def read_file_slice(relative_path: str, start_line: int = 1, end_line: int = 50) -> str:
    """
    Read a specific line range from a file in the codebase.
    Returns the content as a string with line numbers.

    Use this to inspect suspicious code sections identified by other tools.

    Args:
        relative_path: Path relative to codebase root (e.g. 'src/auth/deserializer.py')
        start_line: First line to read (1-indexed)
        end_line: Last line to read (inclusive)
    """
    target = _codebase_root / relative_path
    if not target.exists():
        return f"File not found: {relative_path}"

    lines = target.read_text(encoding="utf-8", errors="replace").splitlines()
    start = max(0, start_line - 1)
    end = min(len(lines), end_line)
    sliced = lines[start:end]
    return "\n".join(f"{start + i + 1:4d} | {line}" for i, line in enumerate(sliced))


@tool
def search_content(substring: str, file_glob: str = "**/*.py") -> str:
    """
    Search for a literal substring or simple pattern across all matching files.
    Returns file path and line number for each match.

    Args:
        substring: The exact string to search for
        file_glob: Glob pattern to restrict which files are searched (default: all .py files)
    """
    matches = []
    for path in _codebase_root.glob(file_glob):
        try:
            for i, line in enumerate(
                path.read_text(encoding="utf-8", errors="replace").splitlines(), start=1
            ):
                if substring in line:
                    rel = path.relative_to(_codebase_root)
                    matches.append(f"{rel}:{i}: {line.strip()}")
                    if len(matches) >= 30:
                        break
        except OSError:
            continue
        if len(matches) >= 30:
            break

    if not matches:
        return f"No matches for '{substring}'."
    return "\n".join(matches)
