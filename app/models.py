"""API and workspace Pydantic models for Risk Assessment Agent v2."""

from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, Field


class ScanCreateRequest(BaseModel):
    """Blueprint / target payload that kicks off a scan."""

    cve_id: str
    codebase_path: str
    target_name: Optional[str] = None
    blueprint: Optional[dict[str, Any]] = None
    blueprint_path: Optional[str] = None
    product_docs_path: Optional[str] = None
    sbom: Optional[dict[str, Any]] = None
    extra: dict[str, Any] = Field(default_factory=dict)


class ScanCreateResponse(BaseModel):
    scan_id: str
    status: str = "running"
    message: str = "Scan started"


class CompletedScanSummary(BaseModel):
    scan_id: str
    status: str
    target_name: Optional[str] = None
    cve_id: Optional[str] = None
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    elapsed_seconds: Optional[float] = None


class ScanSnapshot(BaseModel):
    """Unified view of a scan's workspace artefacts."""

    scan_id: str
    status: dict[str, Any]
    request: Optional[dict[str, Any]] = None
    plan: Optional[dict[str, Any]] = None
    skills: dict[str, Any] = Field(default_factory=dict)
    aggregated_evidence: Optional[dict[str, Any]] = None
    mde: Optional[dict[str, Any]] = None
    scoring: Optional[dict[str, Any]] = None
    final_assessment: Optional[dict[str, Any]] = None
