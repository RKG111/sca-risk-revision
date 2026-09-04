"""
The pipeline. This is the only entry point a caller needs.

    assess(sbom, cve_id, codebase_path) -> RiskAssessmentResult

Six steps, in order:

    1. resolve  which component the CVE affects, from the SBOM
    2. lookup   the trusted blueprint for that (CVE, component)
    3. plan     which probes to run and how activation will be judged
    4. gather   run the probes as agents, recording any gaps
    5. decide   the single risk verdict
    6. score    the environmental CVSS

Probes are agents. When one cannot run, the failure is recorded as an evidence
gap and the verdict degrades to inconclusive — never quietly to "safe".
"""

from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path
from typing import Any, Optional

from core import joern, policy, probes as probe_registry, scoring
from core.config import settings
from core.errors import BlueprintNotFound, CoreError, EvidenceUnavailable, JoernUnavailable
from core.models import (
    ActivationState,
    AssessmentPlan,
    Blueprint,
    CycloneDXSBOM,
    EvidenceGap,
    EvidenceSet,
    ProbeId,
    RiskAssessmentResult,
    RiskVerdict,
    Severity,
)
from core.probes import PROBES, ProbeContext
from core.store import BlueprintStore
from core.telemetry import ScanSession
from core.tools import file_tools, joern_mcp_tools, sink_discovery_tools

logger = logging.getLogger(__name__)


async def assess(
    *,
    codebase_path: Path,
    sbom: Optional[CycloneDXSBOM] = None,
    cve_id: Optional[str] = None,
    blueprint: Optional[Blueprint] = None,
    product_docs_path: Optional[Path] = None,
    evidence: Optional[EvidenceSet] = None,
    model: Optional[Any] = None,
    adjudicator: Optional[scoring.Adjudicator] = None,
    use_llm_adjudicator: bool = False,
    scan_id: Optional[str] = None,
    scan_output_dir: Optional[Path] = None,
    scan_output_root: Optional[Path] = None,
    session: Optional[ScanSession] = None,
) -> RiskAssessmentResult:
    """Assess one CVE against one codebase.

    Provide either:
      - `sbom` + `cve_id` (blueprint looked up from the store), or
      - `blueprint` directly (component PURL taken from the blueprint).

    `evidence`, `model` and `adjudicator` exist so tests can supply recorded
    inputs; in production leave evidence/model None. Set
    `use_llm_adjudicator=True` (or pass an adjudicator) for live metric answers.

    Artefacts (conversations, metadata.json, report.json) are written under
    `scan_output_root` when set, otherwise `{scan_output_dir}/{scan_id}/`.
    """
    if blueprint is None:
        if sbom is None or not cve_id:
            raise CoreError("assess requires sbom+cve_id, or an explicit blueprint")
        component_purl = sbom.affected_purl(cve_id)
        if not component_purl:
            raise CoreError(f"SBOM does not say which component {cve_id} affects")
        store = BlueprintStore(settings.blueprint_store_path)
        blueprint = store.get(cve_id, component_purl)
        if not blueprint:
            raise BlueprintNotFound(f"no blueprint for {cve_id} and {component_purl}")
    else:
        cve_id = blueprint.cve_id
        if not blueprint.affected_components:
            raise CoreError(f"blueprint for {cve_id} has no affected_components")
        component_purl = blueprint.affected_components[0].purl

    scan = session or ScanSession.create(
        cve_id=cve_id,
        component_purl=component_purl,
        codebase_path=str(codebase_path),
        scan_id=scan_id,
        output_dir=scan_output_dir,
        output_root=scan_output_root,
    )

    try:
        assessment_plan = policy.plan(blueprint)
        logger.info(
            "[%s] basis=%s probes=%s scan=%s",
            cve_id,
            assessment_plan.activation_basis.value,
            [p.value for p in assessment_plan.probes],
            scan.scan_id,
        )

        if evidence is None:
            evidence = await gather(
                blueprint=blueprint,
                plan=assessment_plan,
                codebase_path=codebase_path,
                product_docs_path=product_docs_path,
                model=model,
                session=scan,
            )

        verdict = policy.decide(assessment_plan, evidence)
        active_adjudicator = adjudicator
        if active_adjudicator is None and use_llm_adjudicator:
            active_adjudicator = scoring.make_llm_adjudicator(session=scan)

        report = build_report(
            blueprint=blueprint,
            component_purl=component_purl,
            plan=assessment_plan,
            evidence=evidence,
            verdict=verdict,
            adjudicator=active_adjudicator,
        )
        report = report.model_copy(
            update={"scan_id": scan.scan_id, "scan_dir": str(scan.root)}
        )
        scan.finish(status="completed", report=report, plan=assessment_plan)
        return report
    except Exception as exc:
        scan.finish(status="failed", error=str(exc))
        raise


# ─────────────────────────────────────────────────────────────────────────────
# Evidence gathering
# ─────────────────────────────────────────────────────────────────────────────


async def gather(
    *,
    blueprint: Blueprint,
    plan: AssessmentPlan,
    codebase_path: Path,
    product_docs_path: Optional[Path] = None,
    model: Optional[Any] = None,
    session: Optional[ScanSession] = None,
) -> EvidenceSet:
    """Run the planned probes and collect their evidence.

    Accuracy policy: when the plan needs Joern (invocation sink gate, hybrid,
    or inclusion presence), a missing CPG or missing mcp-joern tools is a hard
    failure — never a filesystem-only downgrade.
    """
    evidence = EvidenceSet()
    if plan.skip_rescoring:
        logger.info("Activation basis is unknown; running no probes")
        return evidence

    needs_cpg = _requires_joern(plan)
    cpg_info = await _try_index(codebase_path)
    if session is not None:
        session.extra["cpg"] = cpg_info or {
            "indexed": False,
            "error": "joern unavailable or empty CPG",
        }
        if cpg_info:
            (session.root / "cpg.json").write_text(
                json.dumps(cpg_info, indent=2, default=str) + "\n", encoding="utf-8"
            )
    if needs_cpg and not cpg_info:
        raise JoernUnavailable(
            "this assessment requires a Joern CPG; Joern is unavailable and no fallback is permitted"
        )

    if plan.presence_check:
        await _record_presence(evidence, blueprint, cpg_ready=True)

    probe_ids = list(plan.probes)
    if plan.sink_gate and ProbeId.EXPLOIT_PATH in probe_ids:
        if not await _sinks_worth_probing(evidence, blueprint):
            probe_ids = _without(probe_ids, ProbeId.EXPLOIT_PATH)

    ctx = ProbeContext(
        blueprint=blueprint,
        codebase=codebase_path,
        product_docs=product_docs_path,
        cpg_ready=True if needs_cpg else cpg_info is not None,
        session=session,
    )

    needs_mcp = any(PROBES[p].wants_cpg for p in probe_ids)
    async with joern_mcp_tools() as cpg_tools:
        if needs_mcp and not cpg_tools:
            raise JoernUnavailable(
                "mcp-joern CPG tools are unavailable; cannot run exploit-path analysis without Joern"
            )
        base_tools = file_tools(codebase_path, product_docs_path)
        discovery = sink_discovery_tools() if needs_cpg or needs_mcp else []
        for wave in _waves(probe_ids):
            await _run_wave(wave, ctx, evidence, base_tools, cpg_tools, model, discovery)

    return evidence


def _requires_joern(plan: AssessmentPlan) -> bool:
    """True when accuracy depends on a Joern CPG for this plan."""
    if plan.presence_check or plan.sink_gate:
        return True
    return any(PROBES[p].wants_cpg for p in plan.probes)


async def _run_wave(
    wave: list[ProbeId],
    ctx: ProbeContext,
    evidence: EvidenceSet,
    base_tools: list,
    cpg_tools: list,
    model: Optional[Any],
    discovery_tools: Optional[list] = None,
) -> None:
    """Run one dependency layer concurrently."""
    ctx.exploit_paths = list(evidence.exploit_paths)
    runnable = [p for p in wave if _dependencies_met(PROBES[p], evidence, ctx)]

    for probe_id in wave:
        if probe_id not in runnable:
            evidence.gaps.append(
                EvidenceGap(probe=probe_id, reason="its prerequisite evidence was not established")
            )

    logger.info("Probe wave: %s", [p.value for p in runnable])
    discovery_tools = discovery_tools or []
    outcomes = await asyncio.gather(
        *(
            probe_registry.run_probe(
                PROBES[probe_id],
                ctx,
                (
                    (discovery_tools + cpg_tools + base_tools)
                    if PROBES[probe_id].wants_cpg
                    else base_tools
                ),
                model,
            )
            for probe_id in runnable
        ),
        return_exceptions=True,
    )

    for probe_id, outcome in zip(runnable, outcomes):
        if isinstance(outcome, EvidenceUnavailable):
            logger.warning("Probe %s produced no evidence: %s", probe_id.value, outcome.reason)
            evidence.gaps.append(EvidenceGap(probe=probe_id, reason=outcome.reason))
        elif isinstance(outcome, BaseException):
            logger.exception("Probe %s failed", probe_id.value)
            evidence.gaps.append(EvidenceGap(probe=probe_id, reason=str(outcome)))
        else:
            probe_registry.absorb(evidence, probe_id, outcome)


def _dependencies_met(probe: probe_registry.Probe, evidence: EvidenceSet, ctx: ProbeContext) -> bool:
    """A dependent probe needs its prerequisite to have run *and* produced input."""
    for dependency in probe.depends_on:
        if not evidence.has_run(dependency):
            return False
        if dependency == ProbeId.EXPLOIT_PATH and not ctx.exploit_paths:
            return False
    return True


def _waves(probe_ids: list[ProbeId]) -> list[list[ProbeId]]:
    """Group probes into dependency layers; everything in a layer runs together."""
    remaining = list(probe_ids)
    done: set[ProbeId] = set()
    waves: list[list[ProbeId]] = []

    while remaining:
        wave = [p for p in remaining if set(PROBES[p].depends_on) <= done]
        if not wave:
            logger.error("Unsatisfiable probe dependencies among %s", [p.value for p in remaining])
            wave = list(remaining)
        waves.append(wave)
        done.update(wave)
        remaining = [p for p in remaining if p not in wave]

    return waves


async def _try_index(codebase_path: Path) -> Optional[dict]:
    """Best-effort CPG build. Callers that require Joern must treat None as failure."""
    try:
        info = await joern.index_codebase(codebase_path)
        if info:
            info = {**info, "indexed": True}
            logger.info("CPG index: %s", info)
        return info
    except CoreError as exc:
        logger.warning("Could not build a CPG: %s", exc)
        return None


async def _record_presence(evidence: EvidenceSet, blueprint: Blueprint, *, cpg_ready: bool) -> None:
    """Component presence via Joern import graph only.

    Accuracy policy: no regex/filesystem fallback. If a CPG is unavailable or
    the query fails, raise — never invent a soft "not imported" answer.
    """
    if not blueprint.affected_components:
        raise JoernUnavailable(
            "inclusion/presence check needs an affected component on the blueprint"
        )
    if not cpg_ready:
        raise JoernUnavailable(
            "inclusion/presence check requires a Joern CPG; no regex fallback is permitted"
        )

    component = blueprint.affected_components[0]
    evidence.presence = await joern.component_presence(component.purl, component.name)


async def _sinks_worth_probing(evidence: EvidenceSet, blueprint: Blueprint) -> bool:
    """Skip the exploit-path probe when the CPG proves no sink is ever called.

    Requires a live Joern CPG. Callers must already have hard-failed if indexing
    did not succeed — this never invents a "worth probing" answer without Joern.
    """
    try:
        if await joern.any_sink_called(blueprint.sinks):
            return True
    except CoreError as exc:
        raise JoernUnavailable(f"sink pre-flight failed: {exc}") from exc

    logger.info("No blueprint sink is called anywhere in the CPG; skipping the exploit-path probe")
    evidence.ran.append(ProbeId.EXPLOIT_PATH)
    evidence.notes[ProbeId.EXPLOIT_PATH.value] = "CPG shows no call site for any blueprint sink"
    return False


def _without(probe_ids: list[ProbeId], drop: ProbeId) -> list[ProbeId]:
    """Drop a probe and everything that transitively depends on it."""
    dropped = {drop}
    keep = list(probe_ids)
    while True:
        remaining = [p for p in keep if p not in dropped and not dropped & set(PROBES[p].depends_on)]
        if len(remaining) == len(keep):
            return remaining
        dropped.update(set(keep) - set(remaining))
        keep = remaining


# ─────────────────────────────────────────────────────────────────────────────
# Report assembly
# ─────────────────────────────────────────────────────────────────────────────


def build_report(
    *,
    blueprint: Blueprint,
    component_purl: str,
    plan: AssessmentPlan,
    evidence: EvidenceSet,
    verdict: RiskVerdict,
    adjudicator: Optional[scoring.Adjudicator] = None,
) -> RiskAssessmentResult:
    """Score the verdict and assemble the report."""
    base_score = float(blueprint.cvss.score)

    if verdict.activation_state == ActivationState.SKIPPED:
        return RiskAssessmentResult(
            cve_id=blueprint.cve_id,
            component_purl=component_purl,
            original_base_vector=blueprint.cvss.vector,
            original_base_score=base_score,
            environmental_vector=blueprint.cvss.vector,
            score=base_score,
            severity=Severity.from_score(base_score),
            rescored=False,
            skipped=True,
            skip_reason=plan.notes,
            exploitable=False,
            reason=verdict.rationale,
            verdict=verdict,
            plan=plan,
            evidence=evidence,
        )

    answers = scoring.adjudicate(blueprint, verdict, evidence, adjudicator=adjudicator)
    vector = scoring.Vector.parse(blueprint.cvss.vector)
    environmental = vector.environmental({a.metric: a.answer for a in answers})
    value, severity = scoring.score(environmental)

    return RiskAssessmentResult(
        cve_id=blueprint.cve_id,
        component_purl=component_purl,
        original_base_vector=blueprint.cvss.vector,
        original_base_score=base_score,
        environmental_vector=environmental,
        score=value,
        severity=severity,
        rescored=True,
        exploitable=verdict.exploitable,
        reason=verdict.rationale,
        verdict=verdict,
        plan=plan,
        metric_answers=answers,
        evidence=evidence,
    )
