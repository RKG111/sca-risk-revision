"""Smoke tests for v2 workspace + skill discovery (no LLM required)."""

from __future__ import annotations

import uuid

from fastapi.testclient import TestClient

from agent.skills import load_skills, order_by_dependencies
from app.main import app
from app.workspace import create_workspace, read_json, update_status, write_json


def test_load_skills_discovers_s1_to_s4():
    skills = load_skills()
    ids = {s.id for s in skills}
    assert {"s1", "s2", "s3", "s4"} <= ids


def test_skill_dependency_order():
    skills = load_skills()
    ordered = order_by_dependencies(skills, ["s2", "s1", "s4"])
    ids = [s.id for s in ordered]
    assert ids.index("s1") < ids.index("s2")
    assert ids.index("s1") < ids.index("s4")


def test_workspace_json_roundtrip(tmp_path, monkeypatch):
    from app import config

    monkeypatch.setattr(config.settings, "workspace_dir", tmp_path)
    scan_id = str(uuid.uuid4())
    create_workspace(scan_id)
    write_json(scan_id, "status.json", {"status": "running"})
    assert read_json(scan_id, "status.json")["status"] == "running"
    assert read_json(scan_id, "missing.json") is None


def test_create_scan_returns_id(tmp_path, monkeypatch):
    from app import config
    from agent import pipeline

    monkeypatch.setattr(config.settings, "workspace_dir", tmp_path)

    # Avoid running the real pipeline (would call Ollama).
    monkeypatch.setattr(pipeline, "run_pipeline", lambda scan_id: None)

    client = TestClient(app)
    response = client.post(
        "/api/v1/scans",
        json={
            "cve_id": "CVE-2020-14343",
            "codebase_path": "/tmp/code",
            "target_name": "demo",
        },
    )
    assert response.status_code == 202
    body = response.json()
    assert body["status"] == "running"
    assert body["scan_id"]
    assert (tmp_path / body["scan_id"] / "request.json").is_file()
    assert (tmp_path / body["scan_id"] / "status.json").is_file()


def test_completed_and_snapshot(tmp_path, monkeypatch):
    from app import config
    from agent import pipeline

    monkeypatch.setattr(config.settings, "workspace_dir", tmp_path)
    monkeypatch.setattr(pipeline, "run_pipeline", lambda scan_id: None)

    client = TestClient(app)
    created = client.post(
        "/api/v1/scans",
        json={"cve_id": "CVE-1", "codebase_path": ".", "target_name": "t"},
    ).json()
    scan_id = created["scan_id"]

    # Still running → not in completed list
    assert client.get("/api/v1/scans/completed").json() == []

    update_status(
        scan_id,
        "completed",
        extra={"completed_at": "2026-07-30T00:00:10+00:00", "started_at": "2026-07-30T00:00:00+00:00"},
    )
    write_json(scan_id, "final_assessment.json", {"verdict": {"score": 5.0}})
    write_json(scan_id, "s1_output.json", {"verdict": "path_found"})

    completed = client.get("/api/v1/scans/completed").json()
    assert len(completed) == 1
    assert completed[0]["scan_id"] == scan_id
    assert completed[0]["elapsed_seconds"] == 10.0

    snap = client.get(f"/api/v1/scans/{scan_id}").json()
    assert snap["status"]["status"] == "completed"
    assert snap["skills"]["s1"]["verdict"] == "path_found"
    assert snap["final_assessment"]["verdict"]["score"] == 5.0
