"""Scan lifecycle REST endpoints."""

from __future__ import annotations

import logging
import uuid
from datetime import datetime
from typing import Any, Optional

from fastapi import APIRouter, BackgroundTasks, HTTPException

from app.models import (
    CompletedScanSummary,
    ScanCreateRequest,
    ScanCreateResponse,
    ScanSnapshot,
)
from app.workspace import (
    create_workspace,
    list_scan_ids,
    read_json,
    scan_dir,
    update_status,
    utc_now_iso,
    write_json,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/scans", tags=["scans"])

SKILL_OUTPUT_FILES = (
    "s1_output.json",
    "s2_output.json",
    "s3_output.json",
    "s4_output.json",
)


def _elapsed_seconds(started_at: Optional[str], completed_at: Optional[str]) -> Optional[float]:
    if not started_at or not completed_at:
        return None
    try:
        start = datetime.fromisoformat(started_at)
        end = datetime.fromisoformat(completed_at)
        return max(0.0, (end - start).total_seconds())
    except ValueError:
        return None


def _target_name(request: Optional[dict[str, Any]], status: dict[str, Any]) -> Optional[str]:
    if status.get("target_name"):
        return status["target_name"]
    if not request:
        return None
    return request.get("target_name") or request.get("cve_id")


@router.post("", response_model=ScanCreateResponse, status_code=202)
async def create_scan(
    payload: ScanCreateRequest,
    background_tasks: BackgroundTasks,
) -> ScanCreateResponse:
    """Initiate a new scan and run the 8-step pipeline in the background."""
    from agent.pipeline import run_pipeline

    scan_id = str(uuid.uuid4())
    create_workspace(scan_id)

    request_data = payload.model_dump()
    write_json(scan_id, "request.json", request_data)

    now = utc_now_iso()
    update_status(
        scan_id,
        "running",
        step="queued",
        extra={
            "started_at": now,
            "cve_id": payload.cve_id,
            "target_name": payload.target_name or payload.cve_id,
            "codebase_path": payload.codebase_path,
        },
    )

    background_tasks.add_task(run_pipeline, scan_id)
    logger.info("scan %s queued", scan_id)
    return ScanCreateResponse(scan_id=scan_id, status="running", message="Scan started")


@router.get("/completed", response_model=list[CompletedScanSummary])
async def list_completed_scans() -> list[CompletedScanSummary]:
    """Return metadata for scans whose status is completed."""
    summaries: list[CompletedScanSummary] = []
    for scan_id in list_scan_ids():
        status = read_json(scan_id, "status.json")
        if not status or status.get("status") != "completed":
            continue
        request = read_json(scan_id, "request.json")
        started = status.get("started_at")
        completed = status.get("completed_at") or status.get("updated_at")
        summaries.append(
            CompletedScanSummary(
                scan_id=scan_id,
                status="completed",
                target_name=_target_name(request, status),
                cve_id=status.get("cve_id") or (request or {}).get("cve_id"),
                started_at=started,
                completed_at=completed,
                elapsed_seconds=_elapsed_seconds(started, completed),
            )
        )
    return summaries


@router.get("/{scan_id}", response_model=ScanSnapshot)
async def get_scan(scan_id: str) -> ScanSnapshot:
    """Comprehensive snapshot of a scan from its workspace files."""
    if not scan_dir(scan_id).is_dir():
        raise HTTPException(status_code=404, detail=f"Scan not found: {scan_id}")

    status = read_json(scan_id, "status.json")
    if status is None:
        raise HTTPException(status_code=404, detail=f"Missing status.json for scan {scan_id}")

    skills: dict[str, Any] = {}
    for filename in SKILL_OUTPUT_FILES:
        data = read_json(scan_id, filename)
        if data is not None:
            key = filename.removesuffix("_output.json")
            skills[key] = data

    return ScanSnapshot(
        scan_id=scan_id,
        status=status,
        request=read_json(scan_id, "request.json"),
        plan=read_json(scan_id, "plan.json"),
        skills=skills,
        aggregated_evidence=read_json(scan_id, "aggregated_evidence.json"),
        mde=read_json(scan_id, "mde_output.json"),
        scoring=read_json(scan_id, "scoring.json"),
        final_assessment=read_json(scan_id, "final_assessment.json"),
    )
