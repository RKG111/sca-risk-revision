"""
The four evidence questions, declared side by side.

A probe is pure declaration: which prompt, which output contract, what context
the agent needs, what it depends on. All four run through the same loop in
`core.agent`, so there is no per-probe machinery to read.

There is no deterministic implementation behind any of these. If a probe cannot
run, it raises EvidenceUnavailable and the gap is recorded in the report.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional, Type

from pydantic import BaseModel

from core.agent import run_agent
from core.models import (
    Blueprint,
    ConditionType,
    DeploymentEvidence,
    EvidenceSet,
    ExploitPath,
    ExploitPathEvidence,
    MisconfigEvidence,
    MitigationEvidence,
    ProbeId,
)
from core.telemetry import ScanSession

_PROMPTS = Path(__file__).parent / "prompts"

_DEPLOYMENT_CONDITIONS = (
    ConditionType.NETWORK_ACCESS,
    ConditionType.PRIVILEGE_REQUIRED,
    ConditionType.USER_INTERACTION,
)


@dataclass
class ProbeContext:
    """Everything a probe may need to describe its task to the agent."""

    blueprint: Blueprint
    codebase: Path
    product_docs: Optional[Path] = None
    cpg_ready: bool = False
    exploit_paths: list[ExploitPath] = field(default_factory=list)
    session: Optional[ScanSession] = None


@dataclass(frozen=True)
class Probe:
    id: ProbeId
    output_model: Type[BaseModel]
    build_context: Callable[[ProbeContext], str]
    depends_on: tuple[ProbeId, ...] = ()
    wants_cpg: bool = False

    @property
    def instructions(self) -> str:
        return (_PROMPTS / f"{self.id.value}.md").read_text(encoding="utf-8")


def _json_block(payload: dict) -> str:
    return f"```json\n{json.dumps(payload, indent=2, default=str)}\n```"


# ─────────────────────────────────────────────────────────────────────────────
# Context builders — one per probe, each showing the agent only what it needs
# ─────────────────────────────────────────────────────────────────────────────


def _exploit_path_context(ctx: ProbeContext) -> str:
    blueprint = ctx.blueprint
    cpg_block = ""
    cpg = ctx.session.extra.get("cpg") if ctx.session else None
    if isinstance(cpg, dict) and cpg.get("indexed"):
        cpg_block = f"""
## CPG index (already built for this scan)
- path: {cpg.get("path")}
- files: {cpg.get("file_count")} methods: {cpg.get("method_count")} calls: {cpg.get("call_count")}
- sample files: {cpg.get("sample_files")}
Call check_connection, then query call sites / flows. Do not skip tools.
"""
    return f"""## Target
Codebase: {ctx.codebase}
Joern CPG: ready (required for this probe)
{cpg_block}
## Blueprint
{_json_block({
    "cve_id": blueprint.cve_id,
    "upstream_artifacts": blueprint.upstream_artifacts.model_dump(),
    "attacker_inputs": blueprint.attacker_inputs,
    "attack_steps": blueprint.attack_steps,
    "affected_features": blueprint.affected_features,
})}

Find every exploit path to the listed sinks using CPG tools. Return ExploitPathEvidence JSON only.
"""


def _misconfig_context(ctx: ProbeContext) -> str:
    blueprint = ctx.blueprint
    conditions = blueprint.conditions_of(ConditionType.CONFIGURATION_REQUIREMENT)
    return f"""## Target
Codebase: {ctx.codebase}

## Blueprint configuration conditions
{_json_block({
    "cve_id": blueprint.cve_id,
    "conditions": [c.model_dump() for c in conditions],
    "affected_features": blueprint.affected_features,
    "mitigations": [m.model_dump() for m in blueprint.mitigations],
})}

Return MisconfigEvidence JSON only.
"""


def _deployment_context(ctx: ProbeContext) -> str:
    blueprint = ctx.blueprint
    conditions = blueprint.conditions_of(*_DEPLOYMENT_CONDITIONS)
    return f"""## Target
Codebase: {ctx.codebase}
Product docs: {ctx.product_docs or "not provided"}

## Blueprint deployment conditions
{_json_block({
    "cve_id": blueprint.cve_id,
    "conditions": [c.model_dump() for c in conditions],
    "attack_steps": blueprint.attack_steps,
})}

Return DeploymentEvidence JSON only.
"""


def _mitigation_context(ctx: ProbeContext) -> str:
    blueprint = ctx.blueprint
    return f"""## Target
Codebase: {ctx.codebase}

## Exploit paths found by S1
{_json_block({"exploit_paths": [p.model_dump() for p in ctx.exploit_paths]})}

## Blueprint mitigations
{_json_block({
    "mitigations": [m.model_dump() for m in blueprint.mitigations],
    "remediation": blueprint.remediation.model_dump(),
})}

Check each path against each mitigation. Return MitigationEvidence JSON only.
"""


# ─────────────────────────────────────────────────────────────────────────────
# The registry
# ─────────────────────────────────────────────────────────────────────────────

PROBES: dict[ProbeId, Probe] = {
    ProbeId.EXPLOIT_PATH: Probe(
        id=ProbeId.EXPLOIT_PATH,
        output_model=ExploitPathEvidence,
        build_context=_exploit_path_context,
        wants_cpg=True,
    ),
    ProbeId.MISCONFIG: Probe(
        id=ProbeId.MISCONFIG,
        output_model=MisconfigEvidence,
        build_context=_misconfig_context,
    ),
    ProbeId.DEPLOYMENT: Probe(
        id=ProbeId.DEPLOYMENT,
        output_model=DeploymentEvidence,
        build_context=_deployment_context,
    ),
    ProbeId.MITIGATION: Probe(
        id=ProbeId.MITIGATION,
        output_model=MitigationEvidence,
        build_context=_mitigation_context,
        depends_on=(ProbeId.EXPLOIT_PATH,),
    ),
}


async def run_probe(
    probe: Probe,
    ctx: ProbeContext,
    tools: list,
    model: Optional[Any] = None,
) -> BaseModel:
    """Run one probe. Raises EvidenceUnavailable if it cannot answer."""
    return await run_agent(
        probe=probe.id.value,
        instructions=probe.instructions,
        context=probe.build_context(ctx),
        tools=tools,
        output_model=probe.output_model,
        model=model,
        session=ctx.session,
    )


def absorb(evidence: EvidenceSet, probe_id: ProbeId, output: BaseModel) -> None:
    """Fold one probe's output into the shared evidence set."""
    if isinstance(output, ExploitPathEvidence):
        evidence.exploit_paths.extend(output.exploit_paths)
    elif isinstance(output, MisconfigEvidence):
        evidence.misconfigurations.extend(output.misconfigurations)
    elif isinstance(output, DeploymentEvidence):
        evidence.deployment_findings.extend(output.deployment_findings)
        evidence.applicability_falsified |= output.applicability_falsified
    elif isinstance(output, MitigationEvidence):
        evidence.mitigations.extend(output.mitigations_by_path)
    else:  # pragma: no cover - guards against an unregistered contract
        raise TypeError(f"no absorb rule for {type(output).__name__}")

    evidence.ran.append(probe_id)
    notes = getattr(output, "notes", "")
    if notes:
        evidence.notes[probe_id.value] = notes
