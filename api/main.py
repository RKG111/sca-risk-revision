"""
HTTP transport over core.pipeline. Deliberately thin: no logic lives here.

    POST /api/v1/analyze              SBOM + CVE id → job
    POST /api/v1/analyze/blueprint    blueprint path + codebase path → job
                                      (artefacts under <codebase>/report/)
    GET  /api/v1/reports/{id}         poll for the result
    GET  /health

Jobs are held in memory, which is fine for a single-process POC and nothing
more. Swap `_JOBS` for Redis or a table when durability is needed.
"""

from __future__ import annotations

import logging
import uuid
from pathlib import Path
from typing import Optional, Union

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from starlette.background import BackgroundTasks

from core.config import settings
from core.errors import CoreError
from core.models import CycloneDXSBOM, RiskAssessmentResult
from core.pipeline import assess
from core.store import load_blueprint

logging.basicConfig(
    level=settings.log_level.upper(),
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="SCA Risk Rescoring Platform",
    description="Context-aware CVE risk assessment: blueprint, agent evidence, environmental CVSS.",
    version="0.3.0-poc",
)
app.add_middleware(
    CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"]
)


class AnalyzeRequest(BaseModel):
    sbom: CycloneDXSBOM
    cve_id: str
    codebase_path: str = "/"
    product_docs_path: Optional[str] = None


class BlueprintAnalyzeRequest(BaseModel):
    """Run an assessment from on-disk blueprint + codebase paths.

    All scan artefacts (conversations, metadata.json, report.json) are written
    to ``<codebase_path>/report/``.
    """

    blueprint_path: str
    codebase_path: str
    product_docs_path: Optional[str] = None


class AnalyzeResponse(BaseModel):
    job_id: str
    status: str = "queued"
    message: str
    report_dir: Optional[str] = None


class JobStatus(BaseModel):
    job_id: str
    status: str = Field(description="queued | running | completed | failed")
    result: Optional[dict] = None
    error: Optional[str] = None
    report_dir: Optional[str] = None


#: job_id -> a status string while pending, or the finished report.
_JOBS: dict[str, Union[str, RiskAssessmentResult]] = {}
#: job_id -> on-disk report directory when the job writes one.
_JOB_REPORT_DIRS: dict[str, str] = {}


def _resolve(candidate: str) -> Path:
    """Interpret a request path relative to CODEBASE_ROOT, or absolutely."""
    rooted = Path(settings.codebase_root) / candidate.lstrip("/")
    if rooted.exists():
        return rooted
    absolute = Path(candidate)
    if absolute.exists():
        return absolute
    raise CoreError(f"path does not exist: {candidate}")


async def _run(job_id: str, request: AnalyzeRequest) -> None:
    _JOBS[job_id] = "running"
    try:
        report = await assess(
            sbom=request.sbom,
            cve_id=request.cve_id,
            codebase_path=_resolve(request.codebase_path),
            product_docs_path=(
                _resolve(request.product_docs_path) if request.product_docs_path else None
            ),
            use_llm_adjudicator=True,
            scan_id=job_id,
        )
    except Exception as exc:
        logger.exception("[%s] assessment failed", job_id)
        _JOBS[job_id] = f"error: {exc}"
        return

    _JOBS[job_id] = report
    if report.scan_dir:
        _JOB_REPORT_DIRS[job_id] = report.scan_dir
    logger.info(
        "[%s] done: exploitable=%s score=%.1f", job_id, report.exploitable, report.score
    )


async def _run_blueprint(job_id: str, request: BlueprintAnalyzeRequest) -> None:
    _JOBS[job_id] = "running"
    try:
        codebase = _resolve(request.codebase_path)
        if not codebase.is_dir():
            raise CoreError(f"codebase_path is not a directory: {codebase}")
        blueprint = load_blueprint(_resolve(request.blueprint_path))
        report_dir = codebase / "report"
        _JOB_REPORT_DIRS[job_id] = str(report_dir)

        report = await assess(
            blueprint=blueprint,
            codebase_path=codebase,
            product_docs_path=(
                _resolve(request.product_docs_path) if request.product_docs_path else None
            ),
            use_llm_adjudicator=True,
            scan_id=job_id,
            scan_output_root=report_dir,
        )
    except Exception as exc:
        logger.exception("[%s] blueprint assessment failed", job_id)
        _JOBS[job_id] = f"error: {exc}"
        return

    _JOBS[job_id] = report
    if report.scan_dir:
        _JOB_REPORT_DIRS[job_id] = report.scan_dir
    logger.info(
        "[%s] done: exploitable=%s score=%.1f dir=%s",
        job_id,
        report.exploitable,
        report.score,
        report.scan_dir,
    )


@app.post("/api/v1/analyze", response_model=AnalyzeResponse, status_code=202, tags=["analysis"])
async def analyze(request: AnalyzeRequest, background: BackgroundTasks) -> AnalyzeResponse:
    job_id = str(uuid.uuid4())
    _JOBS[job_id] = "queued"
    background.add_task(_run, job_id, request)
    return AnalyzeResponse(
        job_id=job_id,
        message=f"Assessment queued for {request.cve_id}; poll /api/v1/reports/{job_id}",
    )


@app.post(
    "/api/v1/analyze/blueprint",
    response_model=AnalyzeResponse,
    status_code=202,
    tags=["analysis"],
)
async def analyze_blueprint(
    request: BlueprintAnalyzeRequest, background: BackgroundTasks
) -> AnalyzeResponse:
    """Assess from blueprint + codebase paths; write artefacts to <codebase>/report/."""
    job_id = str(uuid.uuid4())
    _JOBS[job_id] = "queued"
    try:
        codebase = _resolve(request.codebase_path)
        report_dir = str(codebase / "report")
    except CoreError:
        report_dir = None
    _JOB_REPORT_DIRS[job_id] = report_dir or ""
    background.add_task(_run_blueprint, job_id, request)
    return AnalyzeResponse(
        job_id=job_id,
        report_dir=report_dir,
        message=(
            f"Assessment queued from blueprint; artefacts → {report_dir or '<codebase>/report/'}; "
            f"poll /api/v1/reports/{job_id}"
        ),
    )


@app.get("/api/v1/reports/{job_id}", response_model=JobStatus, tags=["analysis"])
async def report(job_id: str) -> JobStatus:
    if job_id not in _JOBS:
        raise HTTPException(status_code=404, detail=f"unknown job {job_id}")

    report_dir = _JOB_REPORT_DIRS.get(job_id) or None
    entry = _JOBS[job_id]
    if isinstance(entry, RiskAssessmentResult):
        return JobStatus(
            job_id=job_id,
            status="completed",
            result=entry.model_dump(mode="json"),
            report_dir=entry.scan_dir or report_dir,
        )
    if entry.startswith("error:"):
        return JobStatus(
            job_id=job_id,
            status="failed",
            error=entry.removeprefix("error: "),
            report_dir=report_dir,
        )
    return JobStatus(job_id=job_id, status=entry, report_dir=report_dir)


@app.get("/health", tags=["ops"])
async def health() -> dict:
    return {"status": "ok", "version": app.version}
