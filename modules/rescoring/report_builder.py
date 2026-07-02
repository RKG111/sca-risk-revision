"""
Module 5 — Report Builder

Aggregates evidence from Modules 3/4 and the CVSS engine output
into the final RescoredReport document.
"""

import logging
from typing import Optional

from schemas.blueprint import AttackBlueprint
from schemas.report import (
    ConditionResult,
    EvidenceJustification,
    OriginalAssessment,
    RescoredAssessment,
    RescoredReport,
    Severity,
    VerificationMethod,
)
from schemas.sbom import SBOMVulnerability
from modules.rescoring.cvss_engine import CVSSEngine

logger = logging.getLogger(__name__)


class ReportBuilder:
    """
    Constructs the final RescoredReport from all pipeline outputs.
    """

    def __init__(self):
        self.cvss_engine = CVSSEngine()

    def build(
        self,
        vuln: SBOMVulnerability,
        component_purl: str,
        blueprint: AttackBlueprint,
        evidence_items: list[ConditionResult],
    ) -> RescoredReport:
        rating = vuln.primary_rating
        if not rating:
            raise ValueError(f"No CVSS rating available for {vuln.cve_id}")

        reachability = self._determine_reachability(evidence_items)
        verification_method = self._determine_method(evidence_items)
        confidence = self._compute_confidence(evidence_items)

        metric_overrides = None
        if blueprint.suggested_cvss_overrides:
            metric_overrides = blueprint.suggested_cvss_overrides.model_dump(exclude_none=True)

        rescored = self.cvss_engine.rescore(
            original_vector=rating.vector,
            metric_overrides=metric_overrides,
            reachability_verified=reachability,
        )

        execution_trace = self._build_trace(evidence_items, blueprint, reachability)
        env_mitigations = self._build_env_mitigations(blueprint)

        logger.info(
            "%s: %s → %s (%.1f → %.1f)",
            vuln.cve_id,
            rating.severity.upper(),
            rescored.severity,
            rating.score,
            rescored.score,
        )

        return RescoredReport(
            cve_id=vuln.cve_id,
            component=component_purl,
            original_assessment=OriginalAssessment(
                cvss_v3_vector=rating.vector,
                score=rating.score,
                severity=Severity(rating.severity.upper()),
            ),
            rescored_assessment=RescoredAssessment(
                cvss_v3_vector=rescored.vector,
                score=rescored.score,
                severity=Severity(rescored.severity),
            ),
            evidence_justification=EvidenceJustification(
                reachability_verified=reachability,
                execution_trace=execution_trace,
                environmental_mitigations=env_mitigations,
                confidence_score=confidence,
                verification_method=verification_method,
                condition_results=evidence_items,
            ),
        )

    # ── Private helpers ───────────────────────────────────────────────────────

    def _determine_reachability(self, evidence: list[ConditionResult]) -> bool:
        """
        Reachability is verified only if ALL key conditions are met.
        A single failed condition (symbol not called, package not imported)
        is sufficient to mark as not reachable.
        """
        if not evidence:
            return False
        return all(item.result for item in evidence)

    def _determine_method(self, evidence: list[ConditionResult]) -> VerificationMethod:
        methods = {item.method for item in evidence}
        if VerificationMethod.AGENT_LLM in methods and len(methods) > 1:
            return VerificationMethod.HYBRID
        if VerificationMethod.AGENT_LLM in methods:
            return VerificationMethod.AGENT_LLM
        if VerificationMethod.DETERMINISTIC_JOERN in methods:
            return VerificationMethod.DETERMINISTIC_JOERN
        return VerificationMethod.DETERMINISTIC_SEMGREP

    def _compute_confidence(self, evidence: list[ConditionResult]) -> float:
        """
        Higher confidence when more conditions were evaluated and at least
        one used Joern (stronger evidence than Semgrep alone).
        """
        if not evidence:
            return 0.0
        base = min(len(evidence) / 5.0, 1.0)
        has_joern = any(e.method == VerificationMethod.DETERMINISTIC_JOERN for e in evidence)
        return round(min(base + (0.2 if has_joern else 0.0), 1.0), 2)

    def _build_trace(
        self,
        evidence: list[ConditionResult],
        blueprint: AttackBlueprint,
        reachability: bool,
    ) -> str:
        symbol = blueprint.required_conditions.code_level.vulnerable_symbol
        package = blueprint.required_conditions.code_level.package_context

        lines = [f"Vulnerability: {blueprint.cve_id} in {package} ({symbol})"]
        for item in evidence:
            status = "✓" if item.result else "✗"
            lines.append(f"  [{status}] {item.condition_description}: {item.evidence}")

        conclusion = (
            f"REACHABLE — {symbol} is invoked with potentially untrusted input."
            if reachability
            else f"NOT REACHABLE — {symbol} is either not called or adequately guarded."
        )
        lines.append(conclusion)
        return "\n".join(lines)

    def _build_env_mitigations(self, blueprint: AttackBlueprint) -> str:
        env = blueprint.required_conditions.environment_level
        parts = []
        if env.network_exposure:
            parts.append(f"Network exposure: {env.network_exposure}")
        if env.required_feature_flags:
            parts.append(f"Requires feature flags: {', '.join(env.required_feature_flags)}")
        if env.runtime_version_constraints:
            parts.append(f"Runtime constraint: {env.runtime_version_constraints}")
        return "; ".join(parts) if parts else "No specific environmental mitigations identified."
