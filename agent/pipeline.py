"""
Core 8-step Risk Assessment pipeline (v2).

Runs as a FastAPI background task. All state is file-based under
``workspace/{scan_id}/``.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from agent.evidence import aggregate_evidence
from agent.llm import chat, chat_json
from agent.mde import run_mde
from agent.report import build_final_assessment
from agent.scoring import compute_score
from agent.skills import Skill, load_skills, order_by_dependencies
from agent.tools import ToolBundle, prepare_tools
from app.workspace import read_json, update_status, utc_now_iso, write_conversation, write_json

logger = logging.getLogger(__name__)

MAX_TOOL_TURNS = 8

PLAN_SYSTEM = """You are the assessment planner for a vulnerability risk agent.
Given a scan request (CVE / blueprint) and the catalog of available skills,
select which skills to run and in what order.

Respond with ONLY a JSON object:
{
  "selected_skills": ["s1", "s2", ...],
  "rationale": "why these skills",
  "notes": "optional planner notes"
}

Only select skill ids that appear in the catalog. Prefer dependency order.
"""


def run_pipeline(scan_id: str) -> None:
    """Execute the full 8-step pipeline for ``scan_id``."""
    try:
        request = load_blueprint_if_needed(read_json(scan_id, "request.json") or {})
        write_json(scan_id, "request.json", request)
        update_status(scan_id, "running", step="discover_skills")

        # 1. Discover Skills
        skills = discover_skills(scan_id)

        # 2. Plan Assessment
        update_status(scan_id, "running", step="plan_assessment")
        plan = plan_assessment(scan_id, request, skills)

        # 3. Prepare Tools
        update_status(scan_id, "running", step="prepare_tools")
        tools = prepare_tool_bundle(scan_id, request)

        # 4. Run Skills
        update_status(scan_id, "running", step="run_skills")
        skill_outputs = run_skills(scan_id, request, plan, skills, tools)

        # 5. Aggregate Evidence
        update_status(scan_id, "running", step="aggregate_evidence")
        aggregated, mde_input = aggregate_evidence(request, plan, skill_outputs)
        write_json(scan_id, "aggregated_evidence.json", aggregated)
        write_json(scan_id, "mde_input.json", mde_input)

        # 6. Metric Determination Engine
        update_status(scan_id, "running", step="mde")
        mde_output = run_mde(scan_id, mde_input)
        write_json(scan_id, "mde_output.json", mde_output)

        # 7. Scoring
        update_status(scan_id, "running", step="scoring")
        base_vector = mde_input.get("base_vector")
        scoring = compute_score(base_vector, mde_output)
        write_json(scan_id, "scoring.json", scoring)

        # 8. Final Report
        update_status(scan_id, "running", step="final_report")
        final = build_final_assessment(
            scan_id, request, plan, skill_outputs, aggregated, mde_output, scoring
        )
        write_json(scan_id, "final_assessment.json", final)
        update_status(
            scan_id,
            "completed",
            step="done",
            extra={"completed_at": utc_now_iso()},
        )
        logger.info("scan %s completed", scan_id)
    except Exception as exc:
        logger.exception("scan %s failed", scan_id)
        update_status(scan_id, "failed", error=str(exc))


# ── Step implementations ─────────────────────────────────────────────────────


def discover_skills(scan_id: str) -> list[Skill]:
    """Step 1 — load skill definitions from skills/."""
    skills = load_skills()
    catalog = [s.to_dict() for s in skills]
    write_json(scan_id, "skills_catalog.json", {"skills": catalog})
    logger.info("discovered %d skills", len(skills))
    return skills


def plan_assessment(
    scan_id: str,
    request: dict[str, Any],
    skills: list[Skill],
) -> dict[str, Any]:
    """Step 2 — LLM selects skills from the catalog."""
    catalog = [
        {"id": s.id, "name": s.name, "description": s.description, "depends_on": s.depends_on}
        for s in skills
    ]
    user_payload = {
        "request": {
            "cve_id": request.get("cve_id"),
            "target_name": request.get("target_name"),
            "codebase_path": request.get("codebase_path"),
            "blueprint": request.get("blueprint"),
            "blueprint_path": request.get("blueprint_path"),
        },
        "available_skills": catalog,
    }

    if not skills:
        plan = {
            "selected_skills": [],
            "rationale": "No skills available in skills/ directory.",
            "notes": "",
        }
    else:
        try:
            plan = chat_json(
                PLAN_SYSTEM,
                json.dumps(user_payload, indent=2, default=str),
                scan_id=scan_id,
                conversation_name="plan",
            )
        except Exception as exc:
            logger.warning("planner LLM failed (%s); selecting all skills", exc)
            plan = {
                "selected_skills": [s.id for s in skills],
                "rationale": f"Planner fallback after LLM error: {exc}",
                "notes": "fallback",
            }

        selected = plan.get("selected_skills")
        if not isinstance(selected, list) or not selected:
            plan["selected_skills"] = [s.id for s in skills]
            plan.setdefault("notes", "defaulted to all skills")

        # Keep only known skill ids
        known = {s.id for s in skills}
        plan["selected_skills"] = [sid for sid in plan["selected_skills"] if sid in known]

    write_json(scan_id, "plan.json", plan)
    return plan


def prepare_tool_bundle(scan_id: str, request: dict[str, Any]) -> ToolBundle:
    """Step 3 — initialize mock Joern MCP + Graphify CLI."""
    codebase = str(request.get("codebase_path") or ".")
    bundle = prepare_tools(codebase)
    write_json(
        scan_id,
        "tools.json",
        {
            "joern": bundle.joern.meta | {"connected": bundle.joern.connected, "cpg_path": bundle.joern.cpg_path},
            "graphify": bundle.graphify.meta | {"available": bundle.graphify.available},
        },
    )
    return bundle


def run_skills(
    scan_id: str,
    request: dict[str, Any],
    plan: dict[str, Any],
    skills: list[Skill],
    tools: ToolBundle,
) -> dict[str, dict[str, Any]]:
    """Step 4 — execute selected skills in dependency order."""
    ordered = order_by_dependencies(skills, list(plan.get("selected_skills") or []))
    outputs: dict[str, dict[str, Any]] = {}

    for skill in ordered:
        update_status(scan_id, "running", step=f"run_skills:{skill.id}")
        output = run_skill_loop(scan_id, skill, request, tools, prior=outputs)
        write_json(scan_id, skill.output_file, output)
        outputs[skill.id] = output
        logger.info("skill %s finished → %s", skill.id, skill.output_file)

    return outputs


def run_skill_loop(
    scan_id: str,
    skill: Skill,
    request: dict[str, Any],
    tools: ToolBundle,
    *,
    prior: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    """Isolated LLM tool-calling loop for one skill."""
    system = (
        f"You are skill `{skill.id}` ({skill.name}).\n\n"
        f"{skill.body}\n\n"
        "Use tools when needed. When finished, respond with ONLY a JSON object containing:\n"
        "summary, verdict, evidence (list), citations (list), path_gates (list), review_flags (list).\n"
        "Do not invent file/line evidence that tools did not return."
    )
    user = json.dumps(
        {
            "cve_id": request.get("cve_id"),
            "codebase_path": request.get("codebase_path"),
            "blueprint": request.get("blueprint"),
            "prior_skill_outputs": prior,
        },
        indent=2,
        default=str,
    )

    openai_tools = tools.openai_tools(skill.tools or None)
    messages: list[dict[str, Any]] = [
        {"role": "system", "content": system},
        {"role": "user", "content": user},
    ]

    try:
        for _ in range(MAX_TOOL_TURNS):
            response = chat(
                messages,
                tools=openai_tools or None,
                tool_choice="auto" if openai_tools else None,
            )
            message = response.choices[0].message
            tool_calls = getattr(message, "tool_calls", None) or []

            assistant_msg: dict[str, Any] = {
                "role": "assistant",
                "content": message.content or "",
            }
            if tool_calls:
                assistant_msg["tool_calls"] = [
                    {
                        "id": tc.id,
                        "type": "function",
                        "function": {
                            "name": tc.function.name,
                            "arguments": tc.function.arguments,
                        },
                    }
                    for tc in tool_calls
                ]
            messages.append(assistant_msg)

            if not tool_calls:
                break

            for tc in tool_calls:
                name = tc.function.name
                try:
                    args = json.loads(tc.function.arguments or "{}")
                except json.JSONDecodeError:
                    args = {}
                result = tools.dispatch(name, args if isinstance(args, dict) else {})
                messages.append(
                    {
                        "role": "tool",
                        "tool_call_id": tc.id,
                        "content": json.dumps(result, default=str),
                    }
                )

        write_conversation(scan_id, f"skill_{skill.id}", _serializable_messages(messages))
        final_text = messages[-1].get("content") if messages else ""
        if messages and messages[-1].get("role") == "tool":
            # Model never closed the loop — synthesize a stub.
            return _skill_stub(skill, reason="tool_loop_exhausted_without_final_answer")

        parsed = _parse_skill_output(final_text or "", skill)
        return parsed
    except Exception as exc:
        logger.exception("skill %s failed", skill.id)
        write_conversation(scan_id, f"skill_{skill.id}", _serializable_messages(messages))
        return _skill_stub(skill, reason=str(exc))


def _serializable_messages(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return json.loads(json.dumps(messages, default=str))


def _parse_skill_output(text: str, skill: Skill) -> dict[str, Any]:
    text = (text or "").strip()
    if not text:
        return _skill_stub(skill, reason="empty_model_response")

    # Reuse llm JSON extraction logic inline to avoid circular import issues
    from agent.llm import _extract_json

    data = _extract_json(text)
    if data.get("parse_error"):
        return {
            "skill_id": skill.id,
            "summary": "Unparseable skill response",
            "verdict": "inconclusive",
            "evidence": [],
            "citations": [],
            "path_gates": [],
            "review_flags": [{"flag": "parse_error", "raw": data.get("raw")}],
            "raw": data.get("raw"),
        }

    data.setdefault("skill_id", skill.id)
    data.setdefault("summary", "")
    data.setdefault("verdict", "inconclusive")
    data.setdefault("evidence", [])
    data.setdefault("citations", [])
    data.setdefault("path_gates", [])
    data.setdefault("review_flags", [])
    return data


def _skill_stub(skill: Skill, *, reason: str) -> dict[str, Any]:
    return {
        "skill_id": skill.id,
        "summary": f"Skill {skill.id} did not produce a normal result",
        "verdict": "inconclusive",
        "evidence": [],
        "citations": [],
        "path_gates": [],
        "review_flags": [{"flag": "skill_error", "reason": reason}],
        "error": reason,
    }


def load_blueprint_if_needed(request: dict[str, Any]) -> dict[str, Any]:
    """Optionally hydrate request['blueprint'] from blueprint_path."""
    if request.get("blueprint"):
        return request
    path_str = request.get("blueprint_path")
    if not path_str:
        return request
    path = Path(path_str)
    if path.is_file():
        try:
            request["blueprint"] = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            logger.warning("could not load blueprint %s: %s", path, exc)
    return request
