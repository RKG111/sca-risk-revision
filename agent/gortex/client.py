"""HTTP client for the gortex daemon's /v1 tool API.

The daemon exposes every MCP tool at ``POST /v1/tools/{name}``, so the agent
needs no MCP transport and mounts no tool schemas into the model's context.
Responses come back wrapped in an MCP content envelope; ``call`` unwraps it.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Optional

import httpx

logger = logging.getLogger(__name__)


# find_files answers at most 50 rows per call and a bare "**/*" glob does not
# reach deeply nested paths, so enumeration goes one extension at a time.
SOURCE_EXTENSIONS = (
    "py",
    "java",
    "go",
    "js",
    "jsx",
    "ts",
    "tsx",
    "rb",
    "php",
    "cs",
    "kt",
    "rs",
    "scala",
    "c",
    "cc",
    "cpp",
    "h",
    "hpp",
    "ex",
    "exs",
    "swift",
)

_FIND_FILES_PAGE = 50

# Closures are deliberately absent: get_cfg rejects them outright ("needs a
# function or method"), and the extractor elides a closure body from the
# enclosing function's CFG, so their statements carry no def/use facts at all.
CODE_NODE_KINDS = ("function", "method")


class GortexError(RuntimeError):
    """A gortex tool call failed or the daemon is unreachable."""


class GortexClient:
    """Thin synchronous client over the gortex daemon HTTP surface."""

    def __init__(
        self,
        base_url: str = "http://127.0.0.1:7411",
        *,
        auth_token: Optional[str] = None,
        timeout: float = 60.0,
    ) -> None:
        headers = {"Content-Type": "application/json"}
        if auth_token:
            headers["Authorization"] = f"Bearer {auth_token}"
        self._client = httpx.Client(
            base_url=base_url.rstrip("/"),
            timeout=timeout,
            headers=headers,
        )

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "GortexClient":
        return self

    def __exit__(self, *_exc_info) -> None:
        self.close()

    # ── transport ────────────────────────────────────────────────────────────

    def health(self) -> dict[str, Any]:
        try:
            response = self._client.get("/v1/health")
            response.raise_for_status()
        except httpx.HTTPError as exc:
            raise GortexError(f"daemon unreachable: {exc}") from exc
        return response.json()

    def is_up(self) -> bool:
        try:
            return self.health().get("status") == "ok"
        except GortexError:
            return False

    def call(self, tool: str, **arguments: Any) -> Any:
        """Invoke a gortex tool by name and return its unwrapped payload."""
        try:
            response = self._client.post(f"/v1/tools/{tool}", json=arguments)
            response.raise_for_status()
        except httpx.HTTPError as exc:
            raise GortexError(f"{tool} failed: {exc}") from exc

        payload = response.json()
        if isinstance(payload, dict) and payload.get("isError"):
            raise GortexError(f"{tool} returned an error: {_envelope_text(payload)}")
        return _unwrap(payload)

    # ── convenience wrappers ─────────────────────────────────────────────────

    def track(self, path: str) -> Any:
        return self.call("track_repository", path=path)

    def untrack(self, repo: str) -> Any:
        return self.call("untrack_repository", repo=repo)

    def source_files(self, *, repo: Optional[str] = None) -> list[dict[str, Any]]:
        """Indexed source files, optionally confined to one repo.

        Rows carry ``repo``, ``path`` and ``language``; ``path`` is
        repo-relative, so prefix it with ``repo`` to address a file over HTTP
        where there is no working directory to resolve against.
        """
        seen: set[tuple[str, str]] = set()
        files: list[dict[str, Any]] = []
        for extension in SOURCE_EXTENSIONS:
            result = self.call("find_files", glob=f"**/*.{extension}")
            rows = (result or {}).get("files") or []
            if len(rows) >= _FIND_FILES_PAGE:
                logger.warning(
                    "find_files hit its %d-row cap for *.%s — enumeration is "
                    "incomplete for this extension",
                    _FIND_FILES_PAGE,
                    extension,
                )
            for row in rows:
                key = (str(row.get("repo")), str(row.get("path")))
                if key in seen:
                    continue
                seen.add(key)
                files.append(row)
        if repo:
            files = [f for f in files if f.get("repo") == repo]
        return files

    def functions(self, *, repo: Optional[str] = None) -> list[dict[str, Any]]:
        """Callable nodes — functions, methods and closures — with ids and lines.

        Enumerated per file rather than with ``graph_query nodes kind=function``:
        that query silently omits whole repositories even at a high ``limit``,
        so a scan built on it can report an empty result for an indexed repo.
        """
        nodes: list[dict[str, Any]] = []
        for entry in self.source_files(repo=repo):
            path = f"{entry.get('repo')}/{entry.get('path')}"
            try:
                summary = self.call("get_file_summary", path=path)
            except GortexError as exc:
                logger.debug("no summary for %s: %s", path, exc)
                continue
            nodes.extend(
                node
                for node in (summary or {}).get("nodes") or []
                if node.get("kind") in CODE_NODE_KINDS
            )
        return nodes

    def search_symbols(self, query: str, **kwargs: Any) -> list[dict[str, Any]]:
        result = self.call("search_symbols", query=query, **kwargs)
        return (result or {}).get("results") or []

    def get_cfg(self, symbol_id: str) -> dict[str, Any]:
        return self.call("get_cfg", id=symbol_id) or {}

    def def_use(self, symbol_id: str) -> dict[str, Any]:
        return self.call("analyze", kind="def_use", id=symbol_id) or {}

    def contracts(self, **kwargs: Any) -> dict[str, Any]:
        return self.call("contracts", action="list", **kwargs) or {}

    def sast(self, **kwargs: Any) -> dict[str, Any]:
        return self.call("analyze", kind="sast", **kwargs) or {}

    def named_query(self, name: str, **kwargs: Any) -> dict[str, Any]:
        return self.call("analyze", kind="named", name=name, **kwargs) or {}

    def search_text(self, query: str, **kwargs: Any) -> list[dict[str, Any]]:
        result = self.call("search_text", query=query, **kwargs)
        return (result or {}).get("matches") or []


def _envelope_text(payload: dict[str, Any]) -> str:
    parts = [
        block.get("text", "")
        for block in payload.get("content") or []
        if isinstance(block, dict) and block.get("type") == "text"
    ]
    return "\n".join(p for p in parts if p)


def _unwrap(payload: Any) -> Any:
    """Pull the JSON body out of an MCP ``{"content":[{"text": "..."}]}`` envelope."""
    if not isinstance(payload, dict) or "content" not in payload:
        return payload

    text = _envelope_text(payload)
    if not text:
        return payload
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        # Prose-shaped tools (explore's task mode) legitimately return markdown.
        return {"text": text}
