"""
The toolbelt handed to probe agents.

Two families:

  * filesystem tools — read and search the codebase under assessment
  * mcp-joern tools  — CPG queries, exposed by the vendored MCP server
  * local Joern helpers — simple-name call-site lookup (language-agnostic)

Tools are built as closures over the target paths rather than reading module
globals, so two assessments can never see each other's context.

To add another MCP server, add a connection in `_mcp_connections`.
"""

from __future__ import annotations

import logging
import re
import shutil
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, AsyncIterator

import httpx
from langchain_core.tools import tool

from core.config import ROOT, settings

logger = logging.getLogger(__name__)

_MAX_MATCHES = 25
_MAX_FILES = 50


def _relative_glob(
    pattern: str,
    *,
    root: Path | None = None,
    default: str = "**/*",
) -> str:
    """Force a pathlib-safe relative glob. Absolute patterns raise on Path.glob."""
    raw = (pattern or "").strip() or default
    raw = raw.replace("\\", "/")
    if root is not None:
        root_s = str(root.resolve()).replace("\\", "/").rstrip("/")
        # Models often paste absolute paths under the codebase root.
        for prefix in (root_s + "/", root_s):
            if raw.startswith(prefix):
                raw = raw[len(prefix) :].lstrip("/")
                break
            # Also match after a leading slash was already stripped elsewhere.
            if raw.startswith(prefix.lstrip("/")):
                raw = raw[len(prefix.lstrip("/")) :].lstrip("/")
                break
    # Strip absolute / drive prefixes the model often copies from codebase_path.
    if raw.startswith("/"):
        raw = raw.lstrip("/")
    if re.match(r"^[A-Za-z]:[\\/]", raw):
        raw = raw[2:].lstrip("\\/")
    while raw.startswith("./"):
        raw = raw[2:]
    if not raw or raw == "/":
        return default
    return raw


# ─────────────────────────────────────────────────────────────────────────────
# Filesystem tools
# ─────────────────────────────────────────────────────────────────────────────


def file_tools(codebase: Path, product_docs: Path | None = None) -> list:
    """Filesystem tools scoped to one codebase (and optional product docs)."""

    @tool
    def find_files(pattern: str) -> str:
        """Find files by relative glob pattern, e.g. '*.yml' or '*Dockerfile*'.

        Patterns must be relative to the codebase root — do not pass absolute paths.
        """
        try:
            rel = _relative_glob(pattern, root=codebase, default="**/*")
            # Prefer recursive match when the model passes a bare extension glob.
            query = rel if "**" in rel or rel.startswith("*/") else f"**/{rel}"
            matches = sorted(codebase.glob(query))[:_MAX_FILES]
        except (OSError, NotImplementedError, ValueError) as exc:
            return f"Invalid pattern {pattern!r}: {exc}. Use a relative glob like '*.py'."
        if not matches:
            return f"No files matching '{pattern}'."
        return "\n".join(str(p.relative_to(codebase)) for p in matches)

    @tool
    def read_lines(relative_path: str, start_line: int = 1, end_line: int = 80) -> str:
        """Read a 1-indexed inclusive line range from a file relative to the codebase."""
        rel = relative_path.lstrip("/")
        target = (codebase / rel).resolve()
        try:
            target.relative_to(codebase.resolve())
        except ValueError:
            return f"Path escapes codebase: {relative_path}"
        if not target.is_file():
            return f"File not found: {relative_path}"
        lines = target.read_text(encoding="utf-8", errors="replace").splitlines()
        start = max(0, start_line - 1)
        numbered = lines[start:end_line]
        return "\n".join(f"{start + i + 1:4d} | {line}" for i, line in enumerate(numbered))

    @tool
    def search_text(substring: str, file_glob: str = "**/*") -> str:
        """Search for a literal substring across files matching a relative glob."""
        try:
            query = _relative_glob(file_glob, root=codebase, default="**/*")
            paths = list(codebase.glob(query))
        except (OSError, NotImplementedError, ValueError) as exc:
            return (
                f"Invalid file_glob {file_glob!r}: {exc}. "
                "Use a relative glob like '**/*.py' or '*.py'."
            )
        matches: list[str] = []
        for path in paths:
            if not path.is_file():
                continue
            try:
                lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                continue
            for number, line in enumerate(lines, 1):
                if substring in line:
                    matches.append(f"{path.relative_to(codebase)}:{number}: {line.strip()[:160]}")
                    if len(matches) >= _MAX_MATCHES:
                        return "\n".join(matches)
        return "\n".join(matches) if matches else f"No matches for '{substring}'."

    @tool
    def read_product_docs(max_chars: int = 3000) -> str:
        """Read the product documentation, if any was supplied."""
        if not product_docs or not product_docs.exists():
            return "No product docs configured."
        return _docs_text(product_docs, max_chars) or "Product docs empty."

    return [find_files, read_lines, search_text, read_product_docs]


def _docs_text(docs_path: Path, max_chars: int) -> str:
    """Concatenate readable documentation files up to a character budget."""
    if docs_path.is_file():
        return docs_path.read_text(encoding="utf-8", errors="replace")[:max_chars]

    chunks: list[str] = []
    budget = max_chars
    for path in sorted(docs_path.rglob("*")):
        if budget <= 0:
            break
        if not path.is_file() or path.suffix.lower() not in {".md", ".txt", ".rst", ".adoc"}:
            continue
        text = path.read_text(encoding="utf-8", errors="replace")[:budget]
        chunks.append(f"### {path.relative_to(docs_path)}\n{text}")
        budget -= len(text)
    return "\n\n".join(chunks)


# ─────────────────────────────────────────────────────────────────────────────
# Local Joern helpers (simple-name lookup — works for Python/JS/etc.)
# ─────────────────────────────────────────────────────────────────────────────


def _joern_query_sync(cpgql: str) -> Any:
    """Synchronous Joern /query-sync for use inside LangChain tools."""
    auth = None
    if settings.joern_auth_username:
        auth = (settings.joern_auth_username, settings.joern_auth_password)
    with httpx.Client(
        base_url=settings.joern_base_url.rstrip("/"),
        timeout=float(settings.joern_timeout_seconds),
        auth=auth,
    ) as client:
        response = client.post("/query-sync", json={"query": cpgql})
        response.raise_for_status()
        data = response.json()
        if data.get("success") is False:
            raise RuntimeError(data.get("err") or data.get("stderr") or "query rejected")
        if "stdout" in data:
            return data["stdout"]
        return data.get("response", data)


def sink_discovery_tools() -> list:
    """CPG tools that accept blueprint-style symbols (yaml.full_load), not JVM FQNs.

    Prefer these for S1 over mcp-joern get_method_callers(...), which needs exact
    Joern method full names and returns [] for dotted Python names.
    """

    @tool
    def find_call_sites(symbol: str) -> str:
        """Find CPG call sites for a sink symbol by simple method name.

        Pass blueprint symbols such as 'yaml.full_load', 'yaml.load', or 'FullLoader'.
        The last dotted segment is matched via cpg.call.name (language-agnostic).
        Do not use get_method_callers with these names — that tool expects JVM FQNs.
        """
        symbol = (symbol or "").strip()
        if not symbol:
            return "symbol is required (e.g. yaml.full_load)"
        method = symbol.split(".")[-1]
        query = (
            f'cpg.call.name("{method}").map(c => Map('
            f'"file" -> c.file.name.headOption.getOrElse(""), '
            f'"line" -> c.lineNumber.getOrElse(0), '
            f'"code" -> c.code, '
            f'"name" -> c.name'
            f")).l"
        )
        try:
            result = _joern_query_sync(query)
        except Exception as exc:
            return f"Joern query failed for {symbol!r}: {exc}"
        text = str(result or "").strip()
        if not text or ("List()" in text and "Map(" not in text):
            return f"No call sites for {symbol!r} (matched cpg.call.name={method!r})."
        return f"Call sites for {symbol!r} (name={method!r}):\n{text}"

    @tool
    def find_methods_named(symbol: str) -> str:
        """List CPG methods whose simple name matches the last segment of symbol."""
        symbol = (symbol or "").strip()
        if not symbol:
            return "symbol is required"
        method = symbol.split(".")[-1]
        query = (
            f'cpg.method.name("{method}").map(m => Map('
            f'"fullName" -> m.fullName, '
            f'"filename" -> m.filename, '
            f'"line" -> m.lineNumber.getOrElse(0)'
            f")).l"
        )
        try:
            result = _joern_query_sync(query)
        except Exception as exc:
            return f"Joern query failed for {symbol!r}: {exc}"
        text = str(result or "").strip()
        if not text or ("List()" in text and "Map(" not in text):
            return f"No methods named {method!r}."
        return f"Methods named {method!r}:\n{text}"

    return [find_call_sites, find_methods_named]


# ─────────────────────────────────────────────────────────────────────────────
# mcp-joern tools
# ─────────────────────────────────────────────────────────────────────────────


async def _sse_ready(url: str) -> bool:
    try:
        timeout = httpx.Timeout(connect=2.0, read=1.0, write=2.0, pool=2.0)
        async with httpx.AsyncClient(timeout=timeout) as client:
            async with client.stream("GET", url, headers={"Accept": "text/event-stream"}) as response:
                return response.status_code < 500
    except httpx.HTTPError:
        return False


def _stdio_connection() -> dict[str, Any]:
    """Run the vendored MCP server as a subprocess, preferring uv."""
    server_dir = ROOT / "third_party" / "mcp-joern"
    env = {
        "HOST": settings.joern_host,
        "PORT": str(settings.joern_port),
        "USER_NAME": settings.joern_auth_username,
        "PASSWORD": settings.joern_auth_password,
    }
    if shutil.which("uv"):
        return {
            "transport": "stdio",
            "command": "uv",
            "args": ["--directory", str(server_dir), "run", "server.py"],
            "cwd": str(server_dir),
            "env": env,
        }

    interpreter = server_dir / ".venv" / "bin" / "python"
    if not interpreter.is_file():
        raise FileNotFoundError(f"uv not on PATH and no interpreter at {interpreter}")
    return {
        "transport": "stdio",
        "command": str(interpreter),
        "args": [str(server_dir / "server.py")],
        "cwd": str(server_dir),
        "env": env,
    }


async def _mcp_connections() -> dict[str, dict[str, Any]]:
    """One entry per MCP server. SSE when it is up, otherwise a subprocess."""
    url = settings.mcp_joern_url
    if await _sse_ready(url):
        logger.info("mcp-joern over SSE at %s", url)
        return {"joern": {"transport": "sse", "url": url}}

    logger.info("mcp-joern SSE unavailable; starting it over stdio")
    return {"joern": _stdio_connection()}


def _patch_mcp_compat() -> None:
    """mcp >= 1.23 renamed streamablehttp_client; adapters still want the old name."""
    import mcp.client.streamable_http as transport

    if not hasattr(transport, "streamable_http_client") and hasattr(transport, "streamablehttp_client"):
        transport.streamable_http_client = transport.streamablehttp_client


@asynccontextmanager
async def joern_mcp_tools() -> AsyncIterator[list]:
    """Yield mcp-joern CPG tools, or an empty list if the server is unreachable."""
    _patch_mcp_compat()
    from contextlib import AsyncExitStack

    from langchain_mcp_adapters.client import MultiServerMCPClient
    from langchain_mcp_adapters.tools import load_mcp_tools

    try:
        connections = await _mcp_connections()
    except Exception as exc:
        logger.warning("No usable MCP transport: %s", exc)
        yield []
        return

    client = MultiServerMCPClient(connections)
    async with AsyncExitStack() as stack:
        tools: list = []
        try:
            for name in connections:
                session = await stack.enter_async_context(client.session(name))
                loaded = await load_mcp_tools(session)
                logger.info("MCP [%s] exposed %d tool(s)", name, len(loaded))
                tools.extend(loaded)
        except Exception as exc:
            # Only session setup is guarded; failures inside the caller's body
            # must propagate rather than be swallowed by a second yield.
            logger.warning("MCP session setup failed: %s", exc)
            tools = []
        yield tools
