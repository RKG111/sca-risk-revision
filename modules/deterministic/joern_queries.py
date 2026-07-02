"""
Module 3 — Joern CPGQL Query Library

Pre-built queries translated from blueprint conditions.
These queries are executed against the Joern CPG server.

All queries return structured results (list of dicts) that the
DeterministicResolver maps to ConditionResult objects.
"""

import logging
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class QueryResult:
    query_name: str
    found: bool
    details: list[Any]


class JoernQueryLibrary:
    """
    Collection of CPGQL queries for common security patterns.
    Each method returns a QueryResult.
    """

    def __init__(self, joern_client):
        self.client = joern_client

    async def is_symbol_called(self, symbol: str) -> QueryResult:
        """
        Checks if a method/function name is ever called in the CPG.
        Handles dotted names by checking the last component (e.g. 'yaml.load' → 'load').
        """
        method_name = symbol.split(".")[-1]
        cpgql = f'cpg.call.name("{method_name}").l'
        results = await self.client.query(cpgql)
        return QueryResult(
            query_name=f"is_symbol_called:{symbol}",
            found=bool(results),
            details=results if isinstance(results, list) else [],
        )

    async def is_package_imported(self, package_name: str) -> QueryResult:
        """Checks if a package is present in the import graph."""
        top_level = package_name.split(".")[0]
        cpgql = f'cpg.imports.importedAs("{top_level}").l'
        results = await self.client.query(cpgql)
        return QueryResult(
            query_name=f"is_package_imported:{package_name}",
            found=bool(results),
            details=results if isinstance(results, list) else [],
        )

    async def taint_flow_exists(self, source_name: str, sink_name: str) -> QueryResult:
        """
        Checks for a data-flow path from source to sink.
        Used for injection-type vulnerabilities (CWE-89, CWE-78).

        Args:
            source_name: Method name where untrusted data enters (e.g. "request.get")
            sink_name: Method name of the dangerous sink (e.g. "cursor.execute")
        """
        cpgql = (
            f'cpg.call.name("{sink_name}")'
            f'.where(_.argument.reachableBy(cpg.call.name("{source_name}"))).l'
        )
        results = await self.client.query(cpgql)
        return QueryResult(
            query_name=f"taint_flow:{source_name}->{sink_name}",
            found=bool(results),
            details=results if isinstance(results, list) else [],
        )

    async def hardcoded_literal_assigned_to(self, variable_pattern: str) -> QueryResult:
        """
        Detects hardcoded string/bytes literals assigned to security-sensitive variables.
        Used for CWE-798 (hardcoded credentials/secrets).
        """
        cpgql = (
            f'cpg.assignment'
            f'.where(_.target.code("{variable_pattern}"))'
            f'.where(_.source.isLiteral).l'
        )
        results = await self.client.query(cpgql)
        return QueryResult(
            query_name=f"hardcoded_literal:{variable_pattern}",
            found=bool(results),
            details=results if isinstance(results, list) else [],
        )

    async def get_callers_of(self, method_name: str) -> QueryResult:
        """Returns all methods that call the given method — useful for reachability tracing."""
        cpgql = f'cpg.method.name("{method_name}").caller.name.l'
        results = await self.client.query(cpgql)
        return QueryResult(
            query_name=f"callers_of:{method_name}",
            found=bool(results),
            details=results if isinstance(results, list) else [],
        )
