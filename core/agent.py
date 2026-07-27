"""
The one agent loop.

Every probe runs through `run_agent`. A probe supplies instructions, a context
payload, a toolbelt and an output contract; nothing else differs between them,
which is why there is a single loop rather than one per probe.

The loop is deliberately small: call the model, run any tools it asked for,
repeat until it answers or hits the iteration ceiling.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Annotated, Any, Optional, Type, TypeVar

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage
from langgraph.graph import END, START, StateGraph
from langgraph.graph.message import add_messages
from langgraph.prebuilt import ToolNode
from pydantic import BaseModel, ValidationError
from typing_extensions import TypedDict

from core.config import settings
from core.errors import EvidenceUnavailable
from core.llm import chat_model

logger = logging.getLogger(__name__)

T = TypeVar("T", bound=BaseModel)

_EXHAUSTED = "AGENT_ITERATION_LIMIT"
_FENCED_JSON = re.compile(r"```(?:json)?\s*(\{.*?\})\s*```", re.DOTALL)
_BARE_JSON = re.compile(r"(\{.*\})", re.DOTALL)


class _State(TypedDict):
    messages: Annotated[list, add_messages]
    iterations: int


async def run_agent(
    *,
    probe: str,
    instructions: str,
    context: str,
    tools: list,
    output_model: Type[T],
    model: Optional[Any] = None,
    max_iterations: Optional[int] = None,
) -> T:
    """Run one probe to completion and return its typed evidence.

    Raises EvidenceUnavailable when the agent cannot produce valid evidence,
    because an empty result would be indistinguishable from a real negative.
    """
    ceiling = max_iterations or settings.llm_max_iterations
    llm = (model or chat_model()).bind_tools(tools)

    def call_model(state: _State) -> dict:
        if state["iterations"] >= ceiling:
            return {"messages": [AIMessage(content=_EXHAUSTED)]}
        return {
            "messages": [llm.invoke(state["messages"])],
            "iterations": state["iterations"] + 1,
        }

    def next_step(state: _State) -> str:
        last = state["messages"][-1]
        return "tools" if isinstance(last, AIMessage) and last.tool_calls else END

    graph = StateGraph(_State)
    graph.add_node("model", call_model)
    graph.add_node("tools", ToolNode(tools))
    graph.add_edge(START, "model")
    graph.add_conditional_edges("model", next_step, {"tools": "tools", END: END})
    graph.add_edge("tools", "model")

    try:
        final = await graph.compile().ainvoke(
            {
                "messages": [SystemMessage(content=instructions), HumanMessage(content=context)],
                "iterations": 0,
            }
        )
    except Exception as exc:
        raise EvidenceUnavailable(probe, f"agent run failed: {exc}") from exc

    return _parse_evidence(final["messages"], output_model, probe)


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
            return output_model.model_validate(json.loads(match.group(1)))
        except (json.JSONDecodeError, ValidationError) as exc:
            logger.warning("[%s] discarding malformed evidence: %s", probe, exc)

    raise EvidenceUnavailable(probe, f"agent returned no valid {output_model.__name__}")
