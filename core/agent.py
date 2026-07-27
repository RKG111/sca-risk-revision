"""
The one agent loop.

Every probe runs through `run_agent`. A probe supplies instructions, a context
payload, a toolbelt and an output contract; nothing else differs between them,
which is why there is a single loop rather than one per probe.

The loop is deliberately small: call the model, run any tools it asked for,
repeat until it answers or hits the iteration ceiling.

Tool use is the model's decision. The loop does not force tools — but it does
refuse identical tool-call thrashing (same name+args repeated) so empty Joern
queries cannot burn the iteration budget.

When a ScanSession is supplied, the full message transcript and per-turn token
usage are written under that scan's conversations/ directory.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Annotated, Any, Optional, Type, TypeVar

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage, ToolMessage
from langgraph.graph import END, START, StateGraph
from langgraph.graph.message import add_messages
from langgraph.prebuilt import ToolNode
from pydantic import BaseModel, ValidationError
from typing_extensions import TypedDict

from core.config import settings
from core.errors import EvidenceUnavailable
from core.llm import chat_model
from core.telemetry import ScanSession

logger = logging.getLogger(__name__)

T = TypeVar("T", bound=BaseModel)

_EXHAUSTED = "AGENT_ITERATION_LIMIT"
_FENCED_JSON = re.compile(r"```(?:json)?\s*(\{.*?\})\s*```", re.DOTALL)
_BARE_JSON = re.compile(r"(\{.*\})", re.DOTALL)
_THRASH_LIMIT = 2  # identical tool-call signatures allowed before refusal


class _State(TypedDict):
    messages: Annotated[list, add_messages]
    iterations: int


def _tool_call_signature(message: AIMessage) -> str:
    calls = getattr(message, "tool_calls", None) or []
    payload = [
        {"name": tc.get("name", ""), "args": tc.get("args") or {}}
        for tc in calls
    ]
    return json.dumps(payload, sort_keys=True, default=str)


def _signature_count(messages: list, signature: str) -> int:
    count = 0
    for message in messages:
        if isinstance(message, AIMessage) and getattr(message, "tool_calls", None):
            if _tool_call_signature(message) == signature:
                count += 1
    return count


def _refuse_repeated_tools(message: AIMessage) -> list[ToolMessage]:
    """Synthetic tool results that tell the model to change strategy."""
    return [
        ToolMessage(
            content=(
                "REFUSED: this exact tool call (same name and arguments) was already "
                "executed earlier in this probe. Do not repeat it. Change strategy "
                "(different tool or arguments), or return the final evidence JSON now."
            ),
            tool_call_id=tc.get("id") or f"refuse_{i}",
            name=tc.get("name") or "unknown",
        )
        for i, tc in enumerate(message.tool_calls or [])
    ]


async def run_agent(
    *,
    probe: str,
    instructions: str,
    context: str,
    tools: list,
    output_model: Type[T],
    model: Optional[Any] = None,
    max_iterations: Optional[int] = None,
    session: Optional[ScanSession] = None,
) -> T:
    """Run one probe to completion and return its typed evidence.

    Raises EvidenceUnavailable when the agent cannot produce valid evidence,
    because an empty result would be indistinguishable from a real negative.
    """
    ceiling = max_iterations or settings.llm_max_iterations
    llm = (model or chat_model()).bind_tools(tools) if tools else (model or chat_model())
    recorder = session.begin_skill(probe) if session is not None else None
    tool_node = ToolNode(tools) if tools else None

    def call_model(state: _State) -> dict:
        if state["iterations"] >= ceiling:
            return {"messages": [AIMessage(content=_EXHAUSTED)]}
        return {
            "messages": [llm.invoke(state["messages"])],
            "iterations": state["iterations"] + 1,
        }

    def run_tools(state: _State) -> dict:
        last = state["messages"][-1]
        if not isinstance(last, AIMessage) or not last.tool_calls:
            return {"messages": []}
        signature = _tool_call_signature(last)
        prior = _signature_count(state["messages"][:-1], signature)
        if prior >= _THRASH_LIMIT:
            logger.warning("[%s] refusing thrashing tool signature: %s", probe, signature[:200])
            return {"messages": _refuse_repeated_tools(last)}
        assert tool_node is not None
        try:
            return tool_node.invoke(state)
        except Exception as exc:
            # Never let a bad tool arg crash the whole probe (e.g. absolute globs).
            logger.warning("[%s] tool node error: %s", probe, exc)
            return {
                "messages": [
                    ToolMessage(
                        content=f"Tool error: {exc}",
                        tool_call_id=tc.get("id") or f"err_{i}",
                        name=tc.get("name") or "unknown",
                    )
                    for i, tc in enumerate(last.tool_calls or [])
                ]
            }

    def next_step(state: _State) -> str:
        last = state["messages"][-1]
        return "tools" if isinstance(last, AIMessage) and last.tool_calls else END

    graph = StateGraph(_State)
    graph.add_node("model", call_model)
    if tools:
        graph.add_node("tools", run_tools)
        graph.add_conditional_edges("model", next_step, {"tools": "tools", END: END})
        graph.add_edge("tools", "model")
    else:
        graph.add_edge("model", END)
    graph.add_edge(START, "model")

    messages: list = []
    try:
        final = await graph.compile().ainvoke(
            {
                "messages": [SystemMessage(content=instructions), HumanMessage(content=context)],
                "iterations": 0,
            }
        )
        messages = list(final["messages"])
        if recorder is not None:
            recorder.record_messages(messages)
        evidence = _parse_evidence(messages, output_model, probe)
    except EvidenceUnavailable as exc:
        if recorder is not None:
            if messages:
                recorder.record_messages(messages)
            recorder.finish(status="error", error=str(exc))
        raise
    except Exception as exc:
        if recorder is not None:
            if messages:
                recorder.record_messages(messages)
            recorder.finish(status="error", error=f"agent run failed: {exc}")
        raise EvidenceUnavailable(probe, f"agent run failed: {exc}") from exc

    if recorder is not None:
        recorder.finish(status="ok")
    return evidence


def _parse_evidence(messages: list, output_model: Type[T], probe: str) -> T:
    """Pull the last valid instance of the output contract out of the transcript."""
    for message in reversed(messages):
        if not isinstance(message, AIMessage) or not message.content:
            continue
        content = message.content if isinstance(message.content, str) else str(message.content)
        if content.strip() == _EXHAUSTED:
            raise EvidenceUnavailable(probe, "agent hit its iteration limit without answering")

        match = _FENCED_JSON.search(content) or _BARE_JSON.search(content)
        if not match:
            continue
        try:
            payload = json.loads(match.group(1))
        except json.JSONDecodeError as exc:
            logger.warning("[%s] discarding malformed evidence: %s", probe, exc)
            continue
        # Reject JSON that is a fake tool invocation written into content.
        if isinstance(payload, dict):
            keys = set(payload)
            if keys <= {"name", "arguments", "id", "args"} or (
                "name" in payload and "arguments" in payload and "exploit_paths" not in payload
                and "misconfigurations" not in payload
                and "deployment_findings" not in payload
                and "mitigations_by_path" not in payload
            ):
                logger.warning("[%s] discarding tool-shaped JSON posing as evidence", probe)
                continue
        try:
            return output_model.model_validate(payload)
        except ValidationError as exc:
            logger.warning("[%s] discarding malformed evidence: %s", probe, exc)

    raise EvidenceUnavailable(probe, f"agent returned no valid {output_model.__name__}")
