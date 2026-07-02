"""
POST /api/v1/analyze

Accepts an SBOM (JSON body) + a codebase path and a target CVE ID,
then runs the full rescoring pipeline asynchronously.
Returns a job_id that can be polled via GET /api/v1/reports/{job_id}.
"""

import uuid
import asyncio
import logging
from pathlib import Path

from fastapi import APIRouter, BackgroundTasks, HTTPException
from pydantic import BaseModel

from schemas.sbom import CycloneDXSBOM
from schemas.report import RescoredReport
from api.config import settings

logger = logging.getLogger(__name__)
router = APIRouter(tags=["analysis"])

# In-memory job store — replace with Redis/DB in production
_job_store: dict[str, RescoredReport | str] = {}


class AnalysisRequest(BaseModel):
    sbom: CycloneDXSBOM
    cve_id: str
    codebase_path: str = "/"


class AnalysisResponse(BaseModel):
    job_id: str
    status: str = "queued"
    message: str


async def _run_pipeline(job_id: str, request: AnalysisRequest) -> None:
    """
    Orchestrates the 5-module rescoring pipeline for a single CVE.
    Each module is called in sequence; the result is stored under job_id.
    """
    from modules.blueprint.nvd_client import NVDClient
    from modules.blueprint.generator import BlueprintGenerator
    from modules.ingestion.indexer import CodebaseIndexer
    from modules.deterministic.resolver import DeterministicResolver
    from modules.agent.graph import AgentReasoningLoop
    from modules.rescoring.report_builder import ReportBuilder
    from schemas.blueprint import AssessmentStrategy

    try:
        _job_store[job_id] = "running"

        vuln = request.sbom.get_vulnerability(request.cve_id)
        if not vuln:
            raise ValueError(f"CVE {request.cve_id} not found in the provided SBOM")

        component_purl = vuln.affected_purls[0] if vuln.affected_purls else "unknown"
        component = request.sbom.get_component_by_purl(component_purl)

        codebase_path = Path(settings.codebase_root) / request.codebase_path.lstrip("/")

        # ── Module 1: Index the codebase ─────────────────────────────────────
        logger.info("[%s] Module 1: Indexing codebase at %s", job_id, codebase_path)
        indexer = CodebaseIndexer()
        code_index = await indexer.index(codebase_path)

        # ── Module 2: Generate attack blueprint ──────────────────────────────
        logger.info("[%s] Module 2: Generating attack blueprint for %s", job_id, request.cve_id)
        nvd_client = NVDClient()
        nvd_data = await nvd_client.fetch(request.cve_id)
        generator = BlueprintGenerator()
        blueprint = await generator.generate(vuln, nvd_data, component)

        # ── Module 3 or 4: Triage ─────────────────────────────────────────────
        evidence_items = []
        if blueprint.assessment_strategy == AssessmentStrategy.DETERMINISTIC:
            logger.info("[%s] Module 3: Running deterministic triage", job_id)
            resolver = DeterministicResolver()
            evidence_items = await resolver.resolve(blueprint, codebase_path, code_index)
        else:
            logger.info("[%s] Module 4: Running agentic reasoning loop", job_id)
            agent = AgentReasoningLoop()
            evidence_items = await agent.run(blueprint, codebase_path, code_index)

        # ── Module 5: Rescore ─────────────────────────────────────────────────
        logger.info("[%s] Module 5: Computing rescored CVSS", job_id)
        builder = ReportBuilder()
        report = builder.build(
            vuln=vuln,
            component_purl=component_purl,
            blueprint=blueprint,
            evidence_items=evidence_items,
        )

        _job_store[job_id] = report
        logger.info(
            "[%s] Done. Original: %.1f → Rescored: %.1f (delta: %.1f)",
            job_id,
            report.original_assessment.score,
            report.rescored_assessment.score,
            report.score_delta,
        )

    except Exception as exc:
        logger.exception("[%s] Pipeline failed: %s", job_id, exc)
        _job_store[job_id] = f"error: {exc}"


@router.post("/analyze", response_model=AnalysisResponse, status_code=202)
async def submit_analysis(request: AnalysisRequest, background_tasks: BackgroundTasks):
    job_id = str(uuid.uuid4())
    _job_store[job_id] = "queued"
    background_tasks.add_task(_run_pipeline, job_id, request)
    return AnalysisResponse(
        job_id=job_id,
        status="queued",
        message=f"Rescoring job submitted for {request.cve_id}. Poll GET /api/v1/reports/{job_id}",
    )
