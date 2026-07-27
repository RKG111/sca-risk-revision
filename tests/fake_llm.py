"""
Scripted chat model for offline agent tests.

An agent-only architecture has no deterministic code path to compare against,
so determinism comes from replaying a fixed script of model turns instead of
calling Ollama. Each turn is either a set of tool calls or a final answer.
"""

from __future__ import annotations

from typing import Any, Optional

from langchain_core.callbacks import CallbackManagerForLLMRun
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, BaseMessage
from langchain_core.outputs import ChatGeneration, ChatResult
from pydantic import PrivateAttr


class ScriptedChatModel(BaseChatModel):
    """Replays a fixed list of turns, one per invocation.

    A turn is `{"content": "..."}` for a final answer, or
    `{"tool_calls": [{"name": ..., "args": {...}}]}` to drive a tool round-trip.
    """

    turns: list[dict[str, Any]]
    _cursor: int = PrivateAttr(default=0)
    _seen_tools: list[str] = PrivateAttr(default_factory=list)

    @property
    def _llm_type(self) -> str:
        return "scripted"

    def bind_tools(self, tools: list, **kwargs: Any) -> "ScriptedChatModel":
        self._seen_tools = [getattr(t, "name", str(t)) for t in tools]
        return self

    @property
    def bound_tool_names(self) -> list[str]:
        return list(self._seen_tools)

    def _generate(
        self,
        messages: list[BaseMessage],
        stop: Optional[list[str]] = None,
        run_manager: Optional[CallbackManagerForLLMRun] = None,
        **kwargs: Any,
    ) -> ChatResult:
        if self._cursor >= len(self.turns):
            raise AssertionError(
                f"scripted model exhausted after {len(self.turns)} turn(s); "
                "the agent asked for more than the script provides"
            )
        turn = self.turns[self._cursor]
        self._cursor += 1

        tool_calls = [
            {"name": tc["name"], "args": tc.get("args", {}), "id": tc.get("id") or f"call_{i}"}
            for i, tc in enumerate(turn.get("tool_calls") or [])
        ]
        message = AIMessage(content=turn.get("content", ""), tool_calls=tool_calls)
        return ChatResult(generations=[ChatGeneration(message=message)])


class ProbeScriptedChatModel(BaseChatModel):
    """Answers according to which probe's instructions it was handed.

    Probes in a wave run concurrently against one model instance, so replies are
    keyed by probe rather than by call order.
    """

    payloads: dict[str, str]
    _calls: list[str] = PrivateAttr(default_factory=list)

    @property
    def _llm_type(self) -> str:
        return "probe-scripted"

    def bind_tools(self, tools: list, **kwargs: Any) -> "ProbeScriptedChatModel":
        return self

    @property
    def probes_called(self) -> list[str]:
        return list(self._calls)

    def _generate(
        self,
        messages: list[BaseMessage],
        stop: Optional[list[str]] = None,
        run_manager: Optional[CallbackManagerForLLMRun] = None,
        **kwargs: Any,
    ) -> ChatResult:
        system = next(
            (str(m.content) for m in messages if m.__class__.__name__ == "SystemMessage"), ""
        )
        probe = next((p for p in self.payloads if f"# {p} " in system), None)
        if probe is None:
            raise AssertionError(f"no scripted payload for these instructions: {system[:80]!r}")

        self._calls.append(probe)
        return ChatResult(
            generations=[
                ChatGeneration(
                    message=AIMessage(content=f"```json\n{self.payloads[probe]}\n```")
                )
            ]
        )


def final_answer(payload: str) -> list[dict[str, Any]]:
    """Script that answers immediately with a JSON payload."""
    return [{"content": f"```json\n{payload}\n```"}]


def tool_then_answer(
    tool_name: str, tool_args: dict, payload: str
) -> list[dict[str, Any]]:
    """Script that makes one tool call, then answers."""
    return [
        {"tool_calls": [{"name": tool_name, "args": tool_args}]},
        {"content": f"```json\n{payload}\n```"},
    ]
