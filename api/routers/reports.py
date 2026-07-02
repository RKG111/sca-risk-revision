"""
GET /api/v1/reports/{job_id}

Returns the status or final result of a rescoring job.
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Any

router = APIRouter(tags=["reports"])


class JobStatus(BaseModel):
    job_id: str
    status: str
    result: Any = None


@router.get("/reports/{job_id}", response_model=JobStatus)
async def get_report(job_id: str):
    from api.routers.analysis import _job_store
    from schemas.report import RescoredReport

    if job_id not in _job_store:
        raise HTTPException(status_code=404, detail=f"Job {job_id} not found")

    entry = _job_store[job_id]

    if isinstance(entry, RescoredReport):
        return JobStatus(job_id=job_id, status="completed", result=entry.model_dump())
    elif isinstance(entry, str) and entry.startswith("error:"):
        return JobStatus(job_id=job_id, status="failed", result={"message": entry})
    else:
        return JobStatus(job_id=job_id, status=str(entry))
