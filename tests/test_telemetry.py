"""Scan telemetry: conversation logs, token usage, and metadata.json."""

from __future__ import annotations

import json
from pathlib import Path

from core.agent import run_agent
from core.models import CycloneDXSBOM, ExploitPathEvidence
from core.pipeline import assess
from core.telemetry import ScanSession, TokenUsage, usage_from_ai_message
from tests.fake_llm import ScriptedChatModel


VALID_S1 = json.dumps(
    {
        "exploit_paths": [
            {
                "path_id": "path-1",
                "sink": "yaml.full_load",
                "summary": "handler passes body to yaml.full_load",
                "steps": [
                    {
                        "file": "app.py",
                        "line": 13,
                        "symbol": "yaml.full_load",
                        "detail": "data = yaml.full_load(raw)",
                    }
                ],
                "confidence": 0.9,
                "reachable": True,
            }
        ],
        "notes": "one path",
    }
)


class TestTokenUsage:
    def test_from_usage_metadata(self):
        from langchain_core.messages import AIMessage

        message = AIMessage(
            content="ok",
            usage_metadata={"input_tokens": 11, "output_tokens": 7, "total_tokens": 18},
        )
        usage = usage_from_ai_message(message)
        assert usage == TokenUsage(11, 7, 18)

    def test_add(self):
        total = TokenUsage(1, 2, 3)
        total.add(TokenUsage(4, 5, 9))
        assert total.as_dict() == {
            "prompt_tokens": 5,
            "completion_tokens": 7,
            "total_tokens": 12,
        }


class TestAgentConversationLog:
    async def test_records_full_transcript_and_tokens(self, tmp_path, sample_codebase):
        session = ScanSession.create(
            cve_id="CVE-TEST",
            scan_id="scan-agent",
            output_dir=tmp_path,
        )
        from core.tools import file_tools

        script = [
            {
                "tool_calls": [{"name": "search_text", "args": {"substring": "full_load"}}],
                "usage_metadata": {
                    "input_tokens": 100,
                    "output_tokens": 20,
                    "total_tokens": 120,
                },
            },
            {
                "content": f"```json\n{VALID_S1}\n```",
                "usage_metadata": {
                    "input_tokens": 200,
                    "output_tokens": 40,
                    "total_tokens": 240,
                },
            },
        ]
        await run_agent(
            probe="S1",
            instructions="find things",
            context="the context",
            tools=file_tools(sample_codebase),
            output_model=ExploitPathEvidence,
            model=ScriptedChatModel(turns=script),
            session=session,
        )
        session.finish(status="completed")

        conversation = json.loads((tmp_path / "scan-agent" / "conversations" / "S1.json").read_text())
        roles = [m["role"] for m in conversation["messages"]]
        assert roles[0] == "system"
        assert roles[1] == "human"
        assert "ai" in roles
        assert "tool" in roles
        assert conversation["token_usage"]["total_tokens"] == 360
        assert conversation["llm_calls"] == 2

        metadata = json.loads((tmp_path / "scan-agent" / "metadata.json").read_text())
        assert metadata["token_usage"]["total_tokens"] == 360
        assert metadata["token_usage_per_skill"]["S1"]["total_tokens"] == 360
        assert metadata["duration_seconds"] >= 0


class TestAssessMetadata:
    async def test_assess_writes_metadata_and_report(
        self, tmp_path, sample_sbom_dict, sample_codebase, monkeypatch
    ):
        from core.config import settings

        monkeypatch.setattr(settings, "scan_output_dir", str(tmp_path))

        # Pre-supplied evidence: no probes, still get timing + empty skill map.
        from core.models import EvidenceSet, ExploitPath, ExploitPathStep, ProbeId

        evidence = EvidenceSet(
            exploit_paths=[
                ExploitPath(
                    path_id="p1",
                    sink="yaml.full_load",
                    summary="reachable",
                    steps=[
                        ExploitPathStep(
                            file="app.py",
                            line=13,
                            symbol="yaml.full_load",
                            detail="x",
                        )
                    ],
                    confidence=0.9,
                    reachable=True,
                )
            ]
        )
        evidence.ran.append(ProbeId.EXPLOIT_PATH)

        report = await assess(
            sbom=CycloneDXSBOM.model_validate(sample_sbom_dict),
            cve_id="CVE-2020-14343",
            codebase_path=sample_codebase,
            evidence=evidence,
            scan_id="scan-meta",
            scan_output_dir=tmp_path,
        )

        assert report.scan_id == "scan-meta"
        assert report.scan_dir is not None
        root = Path(report.scan_dir)
        assert (root / "metadata.json").is_file()
        assert (root / "report.json").is_file()

        metadata = json.loads((root / "metadata.json").read_text())
        assert metadata["status"] == "completed"
        assert metadata["cve_id"] == "CVE-2020-14343"
        assert "duration_seconds" in metadata
        assert metadata["token_usage"]["total_tokens"] == 0
        assert metadata["report"] == "report.json"
