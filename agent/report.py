"""Step 8 — Compose final_assessment.json."""

from __future__ import annotations

from typing import Any

from app.workspace import utc_now_iso


def build_final_assessment(
    scan_id: str,
    request: dict[str, Any],
    plan: dict[str, Any],
    skill_outputs: dict[str, dict[str, Any]],
    aggregated: dict[str, Any],
    mde_output: dict[str, Any],
    scoring: dict[str, Any],
) -> dict[str, Any]:
    return {
        "scan_id": scan_id,
        "cve_id": request.get("cve_id"),
        "target_name": request.get("target_name") or request.get("cve_id"),
        "codebase_path": request.get("codebase_path"),
        "completed_at": utc_now_iso(),
        "plan": {
            "selected_skills": plan.get("selected_skills"),
            "rationale": plan.get("rationale"),
        },
        "skills": skill_outputs,
        "evidence_summary": {
            "citation_count": len(aggregated.get("citations") or []),
            "path_gate_count": len(aggregated.get("path_gates") or []),
            "review_flag_count": len(aggregated.get("review_flags") or []),
            "findings": aggregated.get("findings") or [],
        },
        "mde": {
            "exploitability_verdict": mde_output.get("exploitability_verdict"),
            "rationale": mde_output.get("rationale"),
            "metrics": mde_output.get("metrics") or {},
        },
        "scoring": {
            "base_vector": scoring.get("base_vector"),
            "environmental_vector": scoring.get("environmental_vector"),
            "score": scoring.get("score"),
            "severity": scoring.get("severity"),
            "base_score": scoring.get("base_score"),
        },
        "verdict": {
            "exploitability": mde_output.get("exploitability_verdict"),
            "severity": scoring.get("severity"),
            "score": scoring.get("score"),
        },
    }
