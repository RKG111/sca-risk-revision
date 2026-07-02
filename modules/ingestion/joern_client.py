"""
Module 1 — Joern CPG Client

Communicates with the Joern REST server running in Docker.
Joern is started with:  joern --server --serverHost 0.0.0.0 --serverPort 8080

Two main operations:
  1. create_cpg(codebase_path)  — Tells Joern to parse a codebase and build the CPG
  2. query(cpgql_query)          — Sends a CPGQL query and returns the results
"""

import logging
from pathlib import Path
from typing import Any

import httpx

from api.config import settings

logger = logging.getLogger(__name__)


class JoernClientError(Exception):
    pass


class JoernClient:
    """
    Thin async wrapper around the Joern REST API.
    All paths passed to Joern must be container-internal paths
    (i.e. under /codebases/ as mounted in docker-compose).
    """

    def __init__(self):
        self.base_url = settings.joern_base_url
        self._client = httpx.AsyncClient(base_url=self.base_url, timeout=120.0)

    async def health_check(self) -> bool:
        try:
            resp = await self._client.get("/v1/version")
            return resp.status_code == 200
        except httpx.ConnectError:
            return False

    async def create_cpg(self, container_path: str) -> str:
        """
        Instructs Joern to parse the codebase at container_path and import the CPG.
        Returns the CPG workspace name.

        CPGQL equivalent:
            importCode("/codebases/my-project")
        """
        query = f'importCode("{container_path}")'
        result = await self.query(query)
        logger.info("CPG created for %s: %s", container_path, result)
        return container_path

    async def query(self, cpgql: str) -> Any:
        """
        Executes a CPGQL query against the currently loaded CPG.

        Args:
            cpgql: A valid CPGQL expression string.

        Returns:
            Parsed JSON result from Joern.

        Example queries:
            cpg.call.name("yaml.load").l
            cpg.method.name("deserialize").caller.l
            cpg.imports.importedAs("yaml").l
        """
        payload = {"query": cpgql}
        try:
            resp = await self._client.post("/v1/execute", json=payload)
            resp.raise_for_status()
            data = resp.json()
            if data.get("success") is False:
                raise JoernClientError(f"Joern query failed: {data.get('err', 'unknown error')}")
            return data.get("response", data)
        except httpx.HTTPStatusError as exc:
            raise JoernClientError(f"HTTP error from Joern: {exc}") from exc

    async def find_calls_to_symbol(self, symbol: str) -> list[dict]:
        """
        Finds all call sites to a given method/function name.

        Example: find_calls_to_symbol("yaml.load") returns file + line info.
        """
        cpgql = f'cpg.call.name("{symbol}").map(c => Map("file" -> c.file.name.l, "line" -> c.lineNumber)).l'
        return await self.query(cpgql)

    async def check_data_flow(self, source_pattern: str, sink_pattern: str) -> bool:
        """
        Checks if there is a taint flow from source_pattern to sink_pattern.
        Returns True if at least one path exists.
        """
        cpgql = (
            f'cpg.call.name("{source_pattern}").reachableBy('
            f'cpg.call.name("{sink_pattern}")).l'
        )
        result = await self.query(cpgql)
        return bool(result)

    async def close(self):
        await self._client.aclose()
