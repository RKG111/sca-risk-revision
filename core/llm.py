"""
The only code that talks to the language model.

Two call shapes are needed and no more: a tool-calling chat model for the agent
loop, and a structured-output call for CVSS adjudication.
"""

from __future__ import annotations

import logging
from typing import Any, Optional, Type, TypeVar

from pydantic import BaseModel

from core.config import settings
from core.errors import LLMUnavailable
from core.telemetry import ScanSession, usage_from_openai_completion

logger = logging.getLogger(__name__)

T = TypeVar("T", bound=BaseModel)


def chat_model() -> Any:
    """Tool-calling chat model used by the agent loop."""
    from langchain_openai import ChatOpenAI

    return ChatOpenAI(
        model=settings.resolved_llm_model,
        base_url=settings.llm_base_url,
        api_key=settings.llm_api_key,
        temperature=settings.llm_temperature,
    )


def structured(
    output_model: Type[T],
    system: str,
    user: str,
    *,
    max_retries: int = 2,
    session: Optional[ScanSession] = None,
    skill: str = "MDE",
) -> T:
    """Ask the model for one instance of `output_model`.

    Schema-constrained via instructor, so the model cannot answer off-vocabulary.
    Raises LLMUnavailable rather than returning a default, so the caller decides
    what an unanswered question means.

    When `session` is set, the request/response and token usage are logged under
    that scan's conversations/<skill>.json.
    """
    recorder = session.begin_skill(skill) if session is not None else None
    try:
        import instructor
        from openai import OpenAI

        client = instructor.from_openai(
            OpenAI(base_url=settings.llm_base_url, api_key=settings.llm_api_key)
        )
        result, completion = client.chat.completions.create_with_completion(
            model=settings.resolved_llm_model,
            response_model=output_model,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            max_retries=max_retries,
        )
        if recorder is not None:
            assistant = (
                result.model_dump_json()
                if hasattr(result, "model_dump_json")
                else str(result)
            )
            recorder.record_structured_turn(
                system=system,
                user=user,
                assistant=assistant,
                usage=usage_from_openai_completion(completion),
            )
            recorder.finish(status="ok")
        return result
    except Exception as exc:
        if recorder is not None:
            recorder.record_structured_turn(system=system, user=user, assistant="")
            recorder.finish(status="error", error=str(exc))
        raise LLMUnavailable(str(exc)) from exc
