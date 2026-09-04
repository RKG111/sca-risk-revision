"""Mock / real tool adapters used by skills (Joern MCP, Graphify CLI)."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Optional

logger = logging.getLogger(__name__)


@dataclass
class JoernMCP:
    """Stub for the Joern MCP server (CPG analysis)."""

    endpoint: str = "http://localhost:3000"
    connected: bool = False
    cpg_path: Optional[str] = None
    meta: dict[str, Any] = field(default_factory=dict)

    def connect(self, codebase_path: str) -> dict[str, Any]:
        self.connected = True
        self.cpg_path = f"/mock/cpg/{codebase_path.strip('/').replace('/', '_')}.cpg.bin"
        self.meta = {"codebase_path": codebase_path, "mode": "mock"}
        logger.info("Joern MCP mock connected for %s", codebase_path)
        return {"ok": True, "cpg_path": self.cpg_path, "mode": "mock"}

    def call_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        if not self.connected:
            return {"error": "not_connected"}
        # Mock empty-but-structured responses so the skill loop can proceed.
        return {
            "tool": name,
            "arguments": arguments,
            "result": [],
            "mode": "mock",
            "note": "Joern MCP is mocked; replace with real MCP client later.",
        }

    def openai_tools(self) -> list[dict[str, Any]]:
        """OpenAI function-calling schemas for mocked Joern tools."""
        return [
            {
                "type": "function",
                "function": {
                    "name": "check_connection",
                    "description": "Check whether the Joern MCP server is reachable.",
                    "parameters": {"type": "object", "properties": {}, "additionalProperties": False},
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "find_call_sites",
                    "description": "Find call sites for a method/symbol in the CPG.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "symbol": {"type": "string", "description": "Simple method or symbol name"},
                        },
                        "required": ["symbol"],
                        "additionalProperties": False,
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "find_flows_from_source_call_to_sink_call",
                    "description": "Find data-flow paths from a source call to a sink call.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "source": {"type": "string"},
                            "sink": {"type": "string"},
                        },
                        "required": ["source", "sink"],
                        "additionalProperties": False,
                    },
                },
            },
        ]


@dataclass
class GraphifyCLI:
    """Stub for the Graphify CLI knowledge-graph tool."""

    available: bool = False
    meta: dict[str, Any] = field(default_factory=dict)

    def prepare(self, codebase_path: str) -> dict[str, Any]:
        self.available = True
        self.meta = {"codebase_path": codebase_path, "mode": "mock"}
        logger.info("Graphify CLI mock prepared for %s", codebase_path)
        return {"ok": True, "mode": "mock", "codebase_path": codebase_path}

    def query(self, question: str) -> dict[str, Any]:
        if not self.available:
            return {"error": "not_prepared"}
        return {
            "question": question,
            "nodes": [],
            "mode": "mock",
            "note": "Graphify CLI is mocked; replace with real CLI invocation later.",
        }

    def openai_tools(self) -> list[dict[str, Any]]:
        return [
            {
                "type": "function",
                "function": {
                    "name": "graphify_query",
                    "description": "Query the Graphify knowledge graph for architecture context.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "question": {"type": "string"},
                        },
                        "required": ["question"],
                        "additionalProperties": False,
                    },
                },
            },
        ]


@dataclass
class ToolBundle:
    joern: JoernMCP
    graphify: GraphifyCLI

    def dispatch(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        if name == "graphify_query":
            return self.graphify.query(arguments.get("question", ""))
        if name in {"check_connection", "find_call_sites", "find_flows_from_source_call_to_sink_call"}:
            return self.joern.call_tool(name, arguments)
        return {"error": f"unknown_tool:{name}"}

    def openai_tools(self, names: Optional[list[str]] = None) -> list[dict[str, Any]]:
        all_tools = self.joern.openai_tools() + self.graphify.openai_tools()
        if not names:
            return all_tools
        allow = set(names)
        return [t for t in all_tools if t["function"]["name"] in allow]


def prepare_tools(codebase_path: str) -> ToolBundle:
    """Initialize mock Joern MCP and Graphify CLI connections."""
    joern = JoernMCP()
    graphify = GraphifyCLI()
    joern.connect(codebase_path)
    graphify.prepare(codebase_path)
    return ToolBundle(joern=joern, graphify=graphify)
