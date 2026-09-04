"""Step 6 — Metric Determination Engine (LLM reasoning over evidence)."""

from __future__ import annotations

import json
import logging
from typing import Any

from agent.llm import chat_json

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are the Metric Determination Engine (MDE) for a vulnerability risk assessment.
Given aggregated evidence and a base CVSS vector, decide modified/environmental CVSS 3.1 metrics
and an exploitability verdict.

Respond with ONLY a JSON object:
{
  "metrics": {
    "MAV": "...", "MAC": "...", "MPR": "...", "MUI": "...", "MS": "...",
    "MC": "...", "MI": "...", "MA": "...",
    "CR": "...", "IR": "...", "AR": "..."
  },
  "environmental_vector": "CVSS:3.1/...",
  "exploitability_verdict": "exploitable|not_exploitable|inconclusive",
  "rationale": "brief justification citing evidence"
}

Use only valid CVSS 3.1 vocabulary. Omit metrics you cannot justify from evidence.
"""


def run_mde(scan_id: str, mde_input: dict[str, Any]) -> dict[str, Any]:
    """LLM step: choose CVSS metrics and exploitability verdict."""
    user = json.dumps(mde_input, indent=2, default=str)
    try:
        result = chat_json(
            SYSTEM_PROMPT,
            user,
            scan_id=scan_id,
            conversation_name="mde",
        )
    except Exception as exc:
        logger.exception("MDE LLM call failed")
        result = {
            "metrics": {},
            "environmental_vector": mde_input.get("base_vector"),
            "exploitability_verdict": "inconclusive",
            "rationale": f"MDE unavailable: {exc}",
            "error": str(exc),
        }

    if "metrics" not in result:
        result["metrics"] = {}
    if "exploitability_verdict" not in result:
        result["exploitability_verdict"] = "inconclusive"
    return result
