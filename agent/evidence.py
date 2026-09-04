"""Step 5 — Aggregate evidence from skill outputs into MDE input."""

from __future__ import annotations

from typing import Any


def aggregate_evidence(
    request: dict[str, Any],
    plan: dict[str, Any],
    skill_outputs: dict[str, dict[str, Any]],
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Deterministically compile citations, path gates, and review flags.

    Returns ``(aggregated_evidence, mde_input)``.
    """
    citations: list[dict[str, Any]] = []
    path_gates: list[dict[str, Any]] = []
    review_flags: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []

    for skill_id, output in skill_outputs.items():
        for citation in output.get("citations") or []:
            item = dict(citation) if isinstance(citation, dict) else {"value": citation}
            item["skill_id"] = skill_id
            citations.append(item)

        for gate in output.get("path_gates") or []:
            item = dict(gate) if isinstance(gate, dict) else {"value": gate}
            item["skill_id"] = skill_id
            path_gates.append(item)

        for flag in output.get("review_flags") or []:
            item = dict(flag) if isinstance(flag, dict) else {"value": flag}
            item["skill_id"] = skill_id
            review_flags.append(item)

        finding = {
            "skill_id": skill_id,
            "summary": output.get("summary"),
            "verdict": output.get("verdict"),
            "evidence": output.get("evidence") or output.get("findings") or [],
        }
        findings.append(finding)

    aggregated = {
        "cve_id": request.get("cve_id"),
        "selected_skills": plan.get("selected_skills") or list(skill_outputs.keys()),
        "citations": citations,
        "path_gates": path_gates,
        "review_flags": review_flags,
        "findings": findings,
        "skill_outputs": skill_outputs,
    }

    blueprint = request.get("blueprint") or {}
    base_vector = None
    if isinstance(blueprint, dict):
        cvss = blueprint.get("cvss") or {}
        base_vector = cvss.get("vector") if isinstance(cvss, dict) else None

    mde_input = {
        "cve_id": request.get("cve_id"),
        "base_vector": base_vector,
        "blueprint": blueprint,
        "aggregated_evidence": {
            "citations": citations,
            "path_gates": path_gates,
            "review_flags": review_flags,
            "findings": findings,
        },
        "instructions": (
            "Decide CVSS environmental / modified base metrics from the evidence. "
            "Return JSON with keys: metrics (object of metric→value), "
            "environmental_vector (string), exploitability_verdict (string), rationale (string)."
        ),
    }
    return aggregated, mde_input
