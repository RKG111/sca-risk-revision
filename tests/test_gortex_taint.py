"""Unit tests for the composed taint analysis, against a stub gortex client.

These pin the behaviours that were wrong in the first working version, all of
which produced plausible-looking but false exploit paths.
"""

from __future__ import annotations

from typing import Any, Optional

from agent.gortex.taint import (
    LATENT_PARAMETER,
    REQUEST_REACHABLE,
    TEXT_ONLY,
    find_taint_paths,
)


def _stmt(line: int, text: str, defs=(), uses=(), kind: Optional[str] = None):
    return {
        "start_line": line,
        "text": text,
        "defs": list(defs),
        "uses": list(uses),
        "kind": kind,
    }


class StubClient:
    """Serves canned CFGs so the tests need no daemon."""

    def __init__(
        self,
        cfgs: dict[str, list[dict[str, Any]]],
        *,
        text_matches: Optional[list[dict[str, Any]]] = None,
    ) -> None:
        self._cfgs = cfgs
        self._text_matches = text_matches or []

    def source_files(self, *, repo: Optional[str] = None) -> list[dict[str, Any]]:
        paths = {sid.split("::")[0] for sid in self._cfgs}
        return [
            {"repo": p.split("/")[0], "path": p.split("/", 1)[1], "language": "python"}
            for p in paths
        ]

    def functions(self, *, repo: Optional[str] = None) -> list[dict[str, Any]]:
        return [
            {
                "id": sid,
                "name": sid.split("::")[-1],
                "kind": "function",
                "file_path": sid.split("::")[0],
            }
            for sid in self._cfgs
        ]

    def get_cfg(self, symbol_id: str) -> dict[str, Any]:
        return {"blocks": [{"label": "body", "statements": self._cfgs[symbol_id]}]}

    def search_text(self, query: str, **_kwargs: Any) -> list[dict[str, Any]]:
        return [m for m in self._text_matches if query in m["text"]]


def test_finds_request_to_sink_in_one_function():
    client = StubClient(
        {
            "r/app.py::handler": [
                _stmt(10, 'raw = request.data.decode("utf-8")', defs=["raw"], uses=["request"]),
                _stmt(11, "data = yaml.full_load(raw)", defs=["data"], uses=["yaml", "raw"]),
            ]
        }
    )
    findings = find_taint_paths(client, sinks=["yaml.full_load"])

    assert len(findings) == 1
    assert findings[0].evidence == REQUEST_REACHABLE
    assert not findings[0].interprocedural
    assert [s.kind for s in findings[0].steps] == ["source", "sink"]
    assert findings[0].steps[-1].line == 11


def test_follows_taint_across_three_functions():
    client = StubClient(
        {
            "r/web.py::upload": [
                _stmt(12, "payload = request.get_data()", defs=["payload"], uses=["request"]),
                _stmt(13, "return handle_upload(payload)", uses=["handle_upload", "payload"]),
            ],
            "r/service.py::handle_upload": [
                _stmt(6, "raw", defs=["raw"], kind="param"),
                _stmt(7, "normalized = raw.strip()", defs=["normalized"], uses=["raw"]),
                _stmt(8, "return parse_document(normalized)", uses=["parse_document", "normalized"]),
            ],
            "r/parser.py::parse_document": [
                _stmt(20, "text", defs=["text"], kind="param"),
                _stmt(21, "return yaml.full_load(text)", uses=["yaml", "text"]),
            ],
        }
    )
    findings = find_taint_paths(client, sinks=["yaml.full_load"])

    reachable = [f for f in findings if f.evidence == REQUEST_REACHABLE]
    assert len(reachable) == 1
    path = reachable[0]
    assert path.crossed_functions == 2
    assert [s.kind for s in path.steps] == ["source", "call", "propagate", "call", "sink"]
    assert path.steps[-1].file == "r/parser.py"


def test_safe_load_is_not_a_load_sink():
    """A substring test for sink `yaml.load` also fires on the mitigation."""
    client = StubClient(
        {
            "r/app.py::handler": [
                _stmt(10, "raw = request.data", defs=["raw"], uses=["request"]),
                _stmt(11, "return yaml.safe_load(raw)", uses=["yaml", "raw"]),
            ]
        }
    )
    assert find_taint_paths(client, sinks=["yaml.load"]) == []


def test_unrelated_identifier_containing_sink_name_is_not_a_sink():
    """`handle_upload` contains the letters of sink `load`."""
    client = StubClient(
        {
            "r/app.py::handler": [
                _stmt(10, "payload = request.get_data()", defs=["payload"], uses=["request"]),
                _stmt(11, "return handle_upload(payload)", uses=["payload"]),
            ]
        }
    )
    assert find_taint_paths(client, sinks=["yaml.load"]) == []


def test_only_the_tainted_parameter_is_cited():
    """A Go handler takes (w, r); only r reaches the sink, so only r is evidence."""
    client = StubClient(
        {
            "r/main.go::handler": [
                _stmt(10, "w", defs=["w"], kind="param"),
                _stmt(10, "r", defs=["r"], kind="param"),
                _stmt(11, "body, _ := io.ReadAll(r.Body)", defs=["body"], uses=["io", "r"]),
                _stmt(12, "err := yaml.Unmarshal(body, &doc)", defs=["err"], uses=["yaml", "body"]),
            ]
        }
    )
    findings = find_taint_paths(
        client, sinks=["yaml.Unmarshal"], entry_points=["r/main.go::handler"]
    )

    assert len(findings) == 1
    cited = [s.variable for s in findings[0].steps if s.kind == "source"]
    assert cited == ["r"]
    assert "w" not in cited


def test_parameter_sink_without_a_caller_is_latent_not_reachable():
    client = StubClient(
        {
            "r/app.py::parse": [
                _stmt(15, "payload", defs=["payload"], kind="param"),
                _stmt(16, "return yaml.load(payload)", uses=["yaml", "payload"]),
            ]
        }
    )
    findings = find_taint_paths(client, sinks=["yaml.load"], include_latent=True)

    assert [f.evidence for f in findings] == [LATENT_PARAMETER]
    assert find_taint_paths(client, sinks=["yaml.load"]) == []


def test_sink_with_no_cfg_is_reported_as_text_only():
    """A sink inside an elided closure body must not read as 'not exploitable'."""
    client = StubClient(
        {"r/main.go::main": [_stmt(10, "r := gin.Default()", defs=["r"], uses=["gin"])]},
        text_matches=[
            {
                "path": "r/main.go",
                "line": 13,
                "text": "c.Redirect(http.StatusFound, target)",
                "symbol_id": "r/main.go::main#closure@+3",
            },
            {
                "path": "r/main.go",
                "line": 3,
                "text": "// documents c.Redirect usage",
                "symbol_id": "",
            },
        ],
    )
    findings = find_taint_paths(client, sinks=["c.Redirect"], include_latent=True)

    # The prose mention on line 3 is not a call site and must be dropped.
    assert len(findings) == 1
    assert findings[0].evidence == TEXT_ONLY
    assert findings[0].steps[0].line == 13
