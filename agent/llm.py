"""LLM client for Ollama via the OpenAI-compatible API."""

from __future__ import annotations

import json
import logging
from typing import Any, Optional

from openai import OpenAI

from app.config import settings
from app.workspace import write_conversation

logger = logging.getLogger(__name__)


def get_client() -> OpenAI:
    """Official OpenAI SDK pointed at the local Ollama endpoint."""
    return OpenAI(
        base_url=settings.llm_base_url,
        api_key=settings.llm_api_key,
    )


def chat(
    messages: list[dict[str, Any]],
    *,
    tools: Optional[list[dict[str, Any]]] = None,
    tool_choice: Optional[str | dict[str, Any]] = None,
    temperature: Optional[float] = None,
    model: Optional[str] = None,
) -> Any:
    """Single chat completion call. Returns the OpenAI response object."""
    client = get_client()
    kwargs: dict[str, Any] = {
        "model": model or settings.llm_model,
        "messages": messages,
        "temperature": settings.llm_temperature if temperature is None else temperature,
    }
    if tools is not None:
        kwargs["tools"] = tools
    if tool_choice is not None:
        kwargs["tool_choice"] = tool_choice
    return client.chat.completions.create(**kwargs)


def chat_json(
    system: str,
    user: str,
    *,
    scan_id: Optional[str] = None,
    conversation_name: Optional[str] = None,
    temperature: Optional[float] = None,
) -> dict[str, Any]:
    """Ask the model for a JSON object; optionally log the conversation."""
    messages: list[dict[str, Any]] = [
        {"role": "system", "content": system},
        {"role": "user", "content": user},
    ]
    response = chat(messages, temperature=temperature)
    content = response.choices[0].message.content or "{}"
    messages.append({"role": "assistant", "content": content})

    if scan_id and conversation_name:
        write_conversation(scan_id, conversation_name, messages)

    return _extract_json(content)


def _extract_json(text: str) -> dict[str, Any]:
    """Best-effort parse of a JSON object from model output."""
    text = text.strip()
    if text.startswith("```"):
        lines = text.splitlines()
        # Drop opening fence and optional language tag, then closing fence
        lines = lines[1:]
        if lines and lines[-1].strip().startswith("```"):
            lines = lines[:-1]
        text = "\n".join(lines).strip()

    try:
        data = json.loads(text)
        if isinstance(data, dict):
            return data
        return {"value": data}
    except json.JSONDecodeError:
        start = text.find("{")
        end = text.rfind("}")
        if start >= 0 and end > start:
            try:
                data = json.loads(text[start : end + 1])
                if isinstance(data, dict):
                    return data
            except json.JSONDecodeError:
                pass
        logger.warning("failed to parse JSON from LLM output")
        return {"raw": text, "parse_error": True}
