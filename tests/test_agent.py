"""
Agent loop and toolbelt tests, driven by a scripted model rather than Ollama.

These cover the behaviour that matters most in an agent-only system: what
happens when the model misbehaves. Every one of those paths must surface as
EvidenceUnavailable, never as empty-but-valid evidence.
"""

from __future__ import annotations

import json

import pytest

from core.agent import run_agent
from core.errors import EvidenceUnavailable
from core.models import ExploitPathEvidence, MisconfigEvidence
from core.tools import file_tools
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


async def _run(script, output_model=ExploitPathEvidence, tools=None, **kwargs):
    return await run_agent(
        probe="S1",
        instructions="find things",
        context="the context",
        tools=tools if tools is not None else [],
        output_model=output_model,
        model=ScriptedChatModel(turns=script),
        **kwargs,
    )


class TestRunAgent:
    async def test_parses_a_fenced_json_answer(self):
        evidence = await _run([{"content": f"```json\n{VALID_S1}\n```"}])
        assert len(evidence.exploit_paths) == 1
        assert evidence.exploit_paths[0].sink == "yaml.full_load"

    async def test_parses_a_bare_json_answer(self):
        evidence = await _run([{"content": VALID_S1}])
        assert len(evidence.exploit_paths) == 1

    async def test_ignores_prose_around_the_json(self):
        evidence = await _run(
            [{"content": f"Here is what I found.\n```json\n{VALID_S1}\n```\nDone."}]
        )
        assert len(evidence.exploit_paths) == 1

    async def test_runs_tools_then_parses_the_answer(self, sample_codebase):
        tools = file_tools(sample_codebase)
        script = [
            {"tool_calls": [{"name": "search_text", "args": {"substring": "full_load"}}]},
            {"content": f"```json\n{VALID_S1}\n```"},
        ]
        evidence = await _run(script, tools=tools)
        assert len(evidence.exploit_paths) == 1

    async def test_no_json_at_all_raises(self):
        with pytest.raises(EvidenceUnavailable, match="no valid ExploitPathEvidence"):
            await _run([{"content": "I could not work it out, sorry."}])

    async def test_malformed_json_raises(self):
        with pytest.raises(EvidenceUnavailable):
            await _run([{"content": "```json\n{\"exploit_paths\": [ oops\n```"}])

    async def test_json_violating_the_contract_raises(self):
        payload = json.dumps({"exploit_paths": [{"summary": "no path_id or sink"}]})
        with pytest.raises(EvidenceUnavailable):
            await _run([{"content": f"```json\n{payload}\n```"}])

    async def test_iteration_limit_raises_rather_than_returning_nothing(self, sample_codebase):
        """A stuck agent must not look like a clean 'nothing found' result."""
        tools = file_tools(sample_codebase)
        looping = [
            {"tool_calls": [{"name": "search_text", "args": {"substring": "x"}}]}
        ] * 4
        with pytest.raises(EvidenceUnavailable, match="iteration limit"):
            await _run(looping, tools=tools, max_iterations=2)

    async def test_an_empty_finding_list_is_a_valid_answer(self):
        """"We looked and found nothing" is legitimate evidence, unlike a failure."""
        payload = json.dumps({"misconfigurations": [], "notes": "searched, nothing unsafe"})
        evidence = await _run(
            [{"content": f"```json\n{payload}\n```"}], output_model=MisconfigEvidence
        )
        assert evidence.misconfigurations == []
        assert evidence.notes == "searched, nothing unsafe"

    async def test_the_last_valid_answer_wins(self):
        first = json.dumps({"exploit_paths": [], "notes": "first attempt"})
        script = [
            {"content": f"```json\n{first}\n```"},
            {"content": f"```json\n{VALID_S1}\n```"},
        ]
        # Only the final message is reachable, since the loop stops when the
        # model answers without tool calls.
        evidence = await _run(script[:1])
        assert evidence.notes == "first attempt"


class TestFileTools:
    def test_tools_are_scoped_to_their_codebase(self, sample_codebase, repo_root):
        scoped = {t.name: t for t in file_tools(sample_codebase)}
        assert "app.py" in scoped["find_files"].invoke({"pattern": "*.py"})

        other = {t.name: t for t in file_tools(repo_root / "core")}
        assert "app.py" not in other["find_files"].invoke({"pattern": "*.py"})

    def test_search_text_reports_file_and_line(self, sample_codebase):
        tools = {t.name: t for t in file_tools(sample_codebase)}
        result = tools["search_text"].invoke({"substring": "full_load"})
        assert "app.py:" in result

    def test_search_text_says_so_when_nothing_matches(self, sample_codebase):
        tools = {t.name: t for t in file_tools(sample_codebase)}
        assert "No matches" in tools["search_text"].invoke({"substring": "zzz-not-here"})

    def test_read_lines_is_one_indexed_and_inclusive(self, sample_codebase):
        tools = {t.name: t for t in file_tools(sample_codebase)}
        result = tools["read_lines"].invoke(
            {"relative_path": "app.py", "start_line": 1, "end_line": 2}
        )
        assert result.splitlines()[0].strip().startswith("1 |")
        assert len(result.splitlines()) == 2

    def test_missing_file_is_reported_not_raised(self, sample_codebase):
        tools = {t.name: t for t in file_tools(sample_codebase)}
        assert "not found" in tools["read_lines"].invoke({"relative_path": "nope.py"}).lower()

    def test_product_docs_are_optional(self, sample_codebase):
        tools = {t.name: t for t in file_tools(sample_codebase)}
        assert "No product docs" in tools["read_product_docs"].invoke({})
