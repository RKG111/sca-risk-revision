"""
The only code in the system that talks to Joern.

Joern is reached over its `/query-sync` HTTP API with basic auth. Agents reach
the same server through mcp-joern tools (see llm.py) — that is a different
transport to the same place, not a second client.

Paths must be container-internal: the repo is bind-mounted into the Joern
container at `JOERN_WORKSPACE_PATH`, so host paths are translated by
`to_container_path`.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Optional

import httpx

from core.config import settings
from core.errors import JoernUnavailable
from core.models import PresenceEvidence
from core.store import package_tokens

logger = logging.getLogger(__name__)


def to_container_path(host_path: Path | str) -> str:
    """Map a host path to its location inside the Joern container."""
    host = Path(host_path).resolve()
    workspace = settings.joern_workspace_path.rstrip("/") or "/app"
    try:
        relative = host.relative_to(Path(settings.codebase_root).resolve())
    except ValueError:
        raw = str(host_path)
        return raw if raw.startswith(f"{workspace}/") else f"{workspace}/{host.name}"
    return f"{workspace}/{relative.as_posix()}"


class Joern:
    """Async Joern client. Use as an async context manager."""

    def __init__(self) -> None:
        auth = None
        if settings.joern_auth_username:
            auth = (settings.joern_auth_username, settings.joern_auth_password)
        self._client = httpx.AsyncClient(
            base_url=settings.joern_base_url.rstrip("/"),
            timeout=float(settings.joern_timeout_seconds),
            auth=auth,
        )

    async def __aenter__(self) -> "Joern":
        return self

    async def __aexit__(self, *_exc_info) -> None:
        await self._client.aclose()

    async def is_up(self) -> bool:
        try:
            response = await self._client.post("/query-sync", json={"query": "version"})
        except httpx.HTTPError:
            return False
        return response.status_code == 200

    async def query(self, cpgql: str) -> Any:
        """Run a CPGQL expression. Returns parsed JSON, or stdout text."""
        try:
            response = await self._client.post("/query-sync", json={"query": cpgql})
            response.raise_for_status()
        except httpx.HTTPError as exc:
            raise JoernUnavailable(f"query failed: {exc}") from exc

        data = response.json()
        if data.get("success") is False:
            raise JoernUnavailable(data.get("err") or data.get("stderr") or "query rejected")
        if "stdout" in data:
            return data["stdout"]
        return data.get("response", data)

    async def import_code(self, host_path: Path | str) -> str:
        """Build a CPG for a codebase. Returns the container path used."""
        container_path = to_container_path(host_path)
        await self.query(f'importCode("{container_path}")')
        logger.info("Built CPG for %s", container_path)
        return container_path

    async def call_sites(self, symbol: str) -> list[dict]:
        """Every call site of a symbol. The only place this query is written."""
        method = symbol.split(".")[-1]
        result = await self.query(
            f'cpg.call.name("{method}").map(c => Map('
            f'"file" -> c.file.name.headOption.getOrElse(""), '
            f'"line" -> c.lineNumber.getOrElse(0), '
            f'"code" -> c.code'
            f")).l"
        )
        return _as_records(result, symbol)

    async def imports_of(self, token: str) -> list[dict]:
        """Import statements mentioning a token, for component presence checks."""
        escaped = token.replace('"', '\\"')
        records: list[dict] = []
        for selector in ("importedAs", "importedEntity"):
            result = await self.query(
                f'cpg.imports.{selector}("(?i).*{escaped}.*").map(i => Map('
                f'"file" -> i.file.name.headOption.getOrElse(""), '
                f'"line" -> i.lineNumber.getOrElse(0), '
                f'"code" -> i.code'
                f")).l"
            )
            records.extend(_as_records(result, token))
        return records


def _as_records(result: Any, symbol: str) -> list[dict]:
    """Normalise Joern's list-of-maps or raw-REPL-string reply into records."""
    if isinstance(result, dict):
        result = [result]
    if not isinstance(result, list):
        text = str(result or "").strip()
        # An empty Scala List means a genuine zero-hit answer.
        if not text or ("List()" in text and "Map(" not in text):
            return []
        return [{"symbol": symbol, "file": "", "line": None, "code": text[:300]}]

    records = []
    for entry in result:
        if not isinstance(entry, dict):
            continue
        line = entry.get("line") or entry.get("lineNumber")
        records.append(
            {
                "symbol": symbol,
                "file": str(entry.get("file") or entry.get("filename") or ""),
                "line": int(line) if line else None,
                "code": str(entry.get("code") or "")[:300],
            }
        )
    return records


async def index_codebase(host_path: Path | str) -> Optional[str]:
    """Build a CPG if Joern is up. Returns the container path, or None."""
    async with Joern() as joern:
        if not await joern.is_up():
            logger.info("Joern is not reachable at %s", settings.joern_base_url)
            return None
        return await joern.import_code(host_path)


async def any_sink_called(sinks: list[str]) -> bool:
    """Whether any blueprint sink is called at all — a cheap pre-flight for S1.

    This is a CPG lookup, not a second opinion on exploitability: it only tells
    us whether asking the agent is worthwhile.
    """
    if not sinks:
        return False
    async with Joern() as joern:
        if not await joern.is_up():
            raise JoernUnavailable("cannot check sink reachability without Joern")
        for sink in sinks:
            if await joern.call_sites(sink):
                return True
    return False


async def component_presence(purl: str, component_name: str | None = None) -> PresenceEvidence:
    """Whether the vulnerable component is imported anywhere in the CPG.

    Import-graph queries only. There is deliberately no textual fallback: a
    regex guess is not evidence, so an unavailable CPG raises instead.
    """
    tokens = package_tokens(purl, component_name)
    if not tokens:
        raise JoernUnavailable(f"no package tokens derived from {purl!r}")

    async with Joern() as joern:
        if not await joern.is_up():
            raise JoernUnavailable("cannot check component presence without Joern")

        seen: set[tuple[str, Optional[int], str]] = set()
        for token in tokens:
            for record in await joern.imports_of(token):
                seen.add((record["file"], record["line"], record["code"]))

    return PresenceEvidence(
        imported=bool(seen),
        tokens=tokens,
        hit_count=len(seen),
        notes=(
            f"CPG import graph matched {len(seen)} import(s)"
            if seen
            else "CPG import graph found no matching imports"
        ),
    )
