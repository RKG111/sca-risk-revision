"""
API tests. The API is pure transport, so these only check request handling,
job lifecycle and error mapping — never risk logic.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from api.main import app
from core.errors import BlueprintNotFound
from core.models import (
    ActivationBasis,
    ActivationState,
    AssessmentPlan,
    RiskAssessmentResult,
    RiskVerdict,
    Severity,
)

BASE_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def payload(sample_sbom_dict, sample_codebase, baseline_cve):
    return {
        "sbom": sample_sbom_dict,
        "cve_id": baseline_cve,
        "codebase_path": str(sample_codebase),
    }


def a_report(cve_id: str) -> RiskAssessmentResult:
    verdict = RiskVerdict(
        activation_basis=ActivationBasis.INVOCATION,
        activation_state=ActivationState.ACTIVATED,
        exploitable=True,
    )
    return RiskAssessmentResult(
        cve_id=cve_id,
        component_purl="pkg:pypi/pyyaml@5.3.1",
        original_base_vector=BASE_VECTOR,
        original_base_score=9.8,
        environmental_vector=BASE_VECTOR,
        score=9.8,
        severity=Severity.CRITICAL,
        exploitable=True,
        reason="exploitable",
        verdict=verdict,
        plan=AssessmentPlan(activation_basis=ActivationBasis.INVOCATION),
    )


def test_health(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_analyze_accepts_a_job_and_completes_it(client, payload, monkeypatch, baseline_cve):
    async def fake_assess(**kwargs):
        assert kwargs["cve_id"] == baseline_cve
        return a_report(baseline_cve)

    monkeypatch.setattr("api.main.assess", fake_assess)

    accepted = client.post("/api/v1/analyze", json=payload)
    assert accepted.status_code == 202
    job_id = accepted.json()["job_id"]

    # TestClient runs background tasks before returning, so the job is done.
    result = client.get(f"/api/v1/reports/{job_id}")
    assert result.status_code == 200
    body = result.json()
    assert body["status"] == "completed"
    assert body["result"]["score"] == 9.8
    assert body["result"]["cve_id"] == baseline_cve


def test_a_failed_assessment_is_reported_as_failed(client, payload, monkeypatch):
    async def failing_assess(**_kwargs):
        raise BlueprintNotFound("no blueprint for CVE-2020-14343")

    monkeypatch.setattr("api.main.assess", failing_assess)

    job_id = client.post("/api/v1/analyze", json=payload).json()["job_id"]
    body = client.get(f"/api/v1/reports/{job_id}").json()
    assert body["status"] == "failed"
    assert "no blueprint" in body["error"]
    assert body["result"] is None


def test_unknown_job_is_404(client):
    assert client.get("/api/v1/reports/not-a-job").status_code == 404


def test_a_malformed_request_is_422(client):
    assert client.post("/api/v1/analyze", json={"cve_id": "CVE-1"}).status_code == 422


def test_a_nonexistent_codebase_path_fails_the_job(client, payload, monkeypatch):
    async def unreached(**_kwargs):  # pragma: no cover
        raise AssertionError("assess should not be reached")

    monkeypatch.setattr("api.main.assess", unreached)

    payload = {**payload, "codebase_path": "/definitely/not/here"}
    job_id = client.post("/api/v1/analyze", json=payload).json()["job_id"]
    body = client.get(f"/api/v1/reports/{job_id}").json()
    assert body["status"] == "failed"
    assert "does not exist" in body["error"]
