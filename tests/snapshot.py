"""
Stable snapshot of a risk assessment, for golden-file comparison.

Deliberately drops anything that varies between identical runs — generated
timestamps, uuid-based ids, and free-text prose — so the golden file pins the
*decision*, not the wording. This lets the same golden pin both the old
pipeline and its replacement.
"""

from __future__ import annotations

from typing import Any


def stable_snapshot(report: Any) -> dict:
    """Reduce a RiskAssessmentResult to its reproducible decision surface."""
    data = report.model_dump(mode="json")

    # Activation lives on `verdict` in the new core and on `evidence_digest` in
    # the pre-rebuild pipeline.
    activation = data.get("verdict") or data.get("evidence_digest") or {}

    return {
        "cve_id": data["cve_id"],
        "component_purl": data["component_purl"],
        "original_base_vector": data["original_base_vector"],
        "environmental_vector": data["environmental_vector"],
        "score": data["score"],
        "severity": data["severity"],
        "rescored": data["rescored"],
        "skipped": data["skipped"],
        "exploitable": data["exploitable"],
        "activation_basis": activation.get("activation_basis"),
        "activation_state": activation.get("activation_state"),
        "metric_answers": sorted(
            ({"metric": m["metric"], "answer": m["answer"]} for m in data["metric_answers"]),
            key=lambda m: m["metric"],
        ),
    }
