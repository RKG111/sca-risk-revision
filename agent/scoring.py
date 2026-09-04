"""Step 7 — Deterministic CVSS environmental scoring."""

from __future__ import annotations

import logging
from typing import Any, Optional

logger = logging.getLogger(__name__)

SEVERITY_BANDS = (
    (0.0, 0.0, "None"),
    (0.1, 3.9, "Low"),
    (4.0, 6.9, "Medium"),
    (7.0, 8.9, "High"),
    (9.0, 10.0, "Critical"),
)


def severity_from_score(score: float) -> str:
    for low, high, label in SEVERITY_BANDS:
        if low <= score <= high:
            return label
    return "Unknown"


def _score_with_cvss_lib(vector: str) -> Optional[dict[str, Any]]:
    try:
        from cvss import CVSS3

        c = CVSS3(vector)
        scores = c.scores()
        sevs = c.severities()
        # scores: (base, temporal, environmental)
        env = float(scores[2]) if scores[2] is not None else float(scores[0])
        sev = sevs[2] if sevs[2] else sevs[0]
        return {
            "score": env,
            "severity": sev.capitalize() if isinstance(sev, str) else severity_from_score(env),
            "base_score": float(scores[0]),
            "engine": "cvss",
        }
    except Exception as exc:
        logger.warning("cvss library scoring failed: %s", exc)
        return None


def compute_score(
    base_vector: Optional[str],
    mde_output: dict[str, Any],
) -> dict[str, Any]:
    """Calculate environmental score/severity from MDE vector + metrics."""
    env_vector = mde_output.get("environmental_vector") or base_vector
    metrics = mde_output.get("metrics") or {}

    # Prefer an explicit environmental vector; otherwise stitch base + modified metrics.
    if not env_vector and base_vector and metrics:
        extras = "/".join(f"{k}:{v}" for k, v in metrics.items() if v)
        env_vector = f"{base_vector}/{extras}" if extras else base_vector

    scored = _score_with_cvss_lib(env_vector) if env_vector else None
    if scored is None:
        # Stub fallback when vector is missing or library cannot parse it.
        scored = {
            "score": None,
            "severity": "Unknown",
            "base_score": None,
            "engine": "stub",
            "note": "Could not compute CVSS score; check environmental_vector.",
        }

    return {
        "base_vector": base_vector,
        "environmental_vector": env_vector,
        "metrics": metrics,
        "score": scored.get("score"),
        "severity": scored.get("severity"),
        "base_score": scored.get("base_score"),
        "exploitability_verdict": mde_output.get("exploitability_verdict"),
        "engine": scored.get("engine"),
        "note": scored.get("note"),
    }
