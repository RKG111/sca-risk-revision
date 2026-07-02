"""
Module 3 — Deterministic Resolver

Translates blueprint conditions into concrete tool invocations
(Semgrep + Joern) and aggregates results into a list of ConditionResult objects.

The resolver is called only when blueprint.assessment_strategy == DETERMINISTIC.
"""

import logging
from pathlib import Path

from schemas.blueprint import AttackBlueprint
from schemas.report import ConditionResult, VerificationMethod

logger = logging.getLogger(__name__)


class DeterministicResolver:
    """
    Evaluates all blueprint conditions using static analysis tools.
    Returns a list of ConditionResult — one per evaluated condition.
    """

    def __init__(self, use_joern: bool = True):
        from modules.deterministic.semgrep_runner import SemgrepRunner
        self.semgrep = SemgrepRunner()
        self.use_joern = use_joern

    async def resolve(
        self,
        blueprint: AttackBlueprint,
        codebase_path: Path,
        code_index,
    ) -> list[ConditionResult]:
        results: list[ConditionResult] = []
        conditions = blueprint.required_conditions

        # ── Check 1: Is the vulnerable package imported? ──────────────────────
        package = conditions.code_level.package_context
        files_importing = code_index.files_importing(package)
        results.append(ConditionResult(
            condition_description=f"Package '{package}' is imported by the codebase",
            result=bool(files_importing),
            evidence=(
                f"Found imports in: {', '.join(files_importing[:5])}"
                if files_importing
                else f"No imports of '{package}' found in any Python file"
            ),
            method=VerificationMethod.DETERMINISTIC_SEMGREP,
        ))

        # ── Check 2: Is the vulnerable symbol called? ─────────────────────────
        symbol = conditions.code_level.vulnerable_symbol
        semgrep_rule = self.semgrep.build_call_check_rule(symbol, blueprint.cve_id)
        symbol_findings = self.semgrep.scan_with_inline_rule(codebase_path, semgrep_rule)
        results.append(ConditionResult(
            condition_description=f"Vulnerable symbol '{symbol}' is called",
            result=bool(symbol_findings),
            evidence=(
                f"Called at: {', '.join(f'{f.file}:{f.line}' for f in symbol_findings[:5])}"
                if symbol_findings
                else f"No calls to '{symbol}' found"
            ),
            method=VerificationMethod.DETERMINISTIC_SEMGREP,
        ))

        # ── Check 3: Reachability indicators ─────────────────────────────────
        for indicator in conditions.code_level.indicators_of_reachability:
            files_with_indicator = code_index.contains_indicator(indicator)
            results.append(ConditionResult(
                condition_description=f"Indicator '{indicator}' present in codebase",
                result=bool(files_with_indicator),
                evidence=(
                    f"Found in: {', '.join(files_with_indicator[:3])}"
                    if files_with_indicator
                    else f"Indicator not found"
                ),
                method=VerificationMethod.DETERMINISTIC_SEMGREP,
            ))

        # ── Check 4: Joern taint flow (if enabled) ────────────────────────────
        if self.use_joern:
            joern_result = await self._check_taint_flow(blueprint, codebase_path)
            if joern_result:
                results.append(joern_result)

        return results

    async def _check_taint_flow(
        self,
        blueprint: AttackBlueprint,
        codebase_path: Path,
    ) -> ConditionResult | None:
        """Uses Joern to verify if a taint flow to the vulnerable symbol exists."""
        try:
            from modules.ingestion.joern_client import JoernClient
            from modules.deterministic.joern_queries import JoernQueryLibrary
            from api.config import settings

            client = JoernClient()
            if not await client.health_check():
                logger.warning("Joern is not reachable, skipping CPG taint analysis")
                return None

            container_path = str(codebase_path).replace(settings.codebase_root, "/codebases")
            await client.create_cpg(container_path)

            lib = JoernQueryLibrary(client)
            symbol = blueprint.required_conditions.code_level.vulnerable_symbol
            query_result = await lib.is_symbol_called(symbol)

            return ConditionResult(
                condition_description=f"Joern CPG: '{symbol}' appears in call graph",
                result=query_result.found,
                evidence=str(query_result.details[:3]) if query_result.details else "No call sites found in CPG",
                method=VerificationMethod.DETERMINISTIC_JOERN,
            )
        except Exception as exc:
            logger.warning("Joern check failed: %s", exc)
            return None
