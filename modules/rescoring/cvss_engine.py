"""
Module 5 — CVSS Rescoring Engine

Uses the official FIRST `cvss` Python library to compute a new CVSS v3.1
score based on evidence-derived metric overrides.

The engine takes:
  - The original CVSS v3.1 vector from NVD
  - Per-metric overrides derived from blueprint + evidence
  - A reachability verdict

And outputs:
  - The new CVSS v3.1 vector string
  - The new base score
  - The severity category
"""

import logging
import re
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)


# CVSS v3.1 metric ordering in the vector string
_VECTOR_ORDER = [
    "AV", "AC", "PR", "UI", "S", "C", "I", "A"
]

# Mapping from blueprint field names to CVSS vector abbreviations
_FIELD_TO_METRIC = {
    "attack_vector": "AV",
    "attack_complexity": "AC",
    "privileges_required": "PR",
    "user_interaction": "UI",
    "scope": "S",
    "confidentiality_impact": "C",
    "integrity_impact": "I",
    "availability_impact": "A",
}


@dataclass
class CVSSResult:
    vector: str
    score: float
    severity: str


class CVSSEngine:
    """
    Applies evidence-based metric overrides to produce a rescored CVSS v3.1 score.
    """

    def rescore(
        self,
        original_vector: str,
        metric_overrides: Optional[dict] = None,
        reachability_verified: bool = True,
    ) -> CVSSResult:
        """
        Applies overrides to the original vector and computes the new score.

        Args:
            original_vector: The NVD CVSS v3.1 vector string
            metric_overrides: Dict of metric abbreviation → new value (e.g. {"AV": "L", "C": "N"})
            reachability_verified: If False, all impact metrics are set to N (not reachable)

        Returns:
            CVSSResult with new vector, score, and severity label
        """
        parsed = self._parse_vector(original_vector)

        if not reachability_verified:
            logger.info(
                "Vulnerability is NOT reachable — setting all impact metrics to N"
            )
            parsed.update({"C": "N", "I": "N", "A": "N"})

        if metric_overrides:
            for field, metric_abbrev in _FIELD_TO_METRIC.items():
                if field in metric_overrides and metric_overrides[field]:
                    new_val = metric_overrides[field]
                    logger.info("Override %s: %s → %s", metric_abbrev, parsed.get(metric_abbrev), new_val)
                    parsed[metric_abbrev] = new_val

            for metric_abbrev, new_val in metric_overrides.items():
                if metric_abbrev.upper() in _VECTOR_ORDER and new_val:
                    parsed[metric_abbrev.upper()] = new_val

        new_vector = self._build_vector(parsed)
        return self._compute(new_vector)

    def compute_from_vector(self, vector: str) -> CVSSResult:
        """Computes score directly from a CVSS v3.1 vector string."""
        return self._compute(vector)

    # ── Private helpers ───────────────────────────────────────────────────────

    def _parse_vector(self, vector: str) -> dict[str, str]:
        """Parses 'CVSS:3.1/AV:N/AC:L/...' into {'AV': 'N', 'AC': 'L', ...}"""
        parts = {}
        for segment in vector.split("/"):
            if ":" in segment and not segment.startswith("CVSS"):
                key, value = segment.split(":", 1)
                parts[key.upper()] = value.upper()
        return parts

    def _build_vector(self, parts: dict[str, str]) -> str:
        """Reconstructs a valid CVSS v3.1 vector string from parts dict."""
        segments = [f"{m}:{parts[m]}" for m in _VECTOR_ORDER if m in parts]
        return "CVSS:3.1/" + "/".join(segments)

    def _compute(self, vector: str) -> CVSSResult:
        try:
            from cvss import CVSS3
            c = CVSS3(vector)
            score = float(c.base_score)
            severity = self._severity_label(score)
            return CVSSResult(vector=vector, score=score, severity=severity)
        except Exception as exc:
            logger.error("CVSS computation failed for vector '%s': %s", vector, exc)
            return CVSSResult(vector=vector, score=0.0, severity="NONE")

    @staticmethod
    def _severity_label(score: float) -> str:
        if score == 0.0:
            return "NONE"
        elif score < 4.0:
            return "LOW"
        elif score < 7.0:
            return "MEDIUM"
        elif score < 9.0:
            return "HIGH"
        return "CRITICAL"
