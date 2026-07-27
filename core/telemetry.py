"""
Per-scan telemetry: full agent↔LLM transcripts, token usage, and metadata.json.

Every `assess` creates a scan directory under `settings.scan_output_dir`:

    runs/<scan_id>/
      metadata.json
      report.json
      conversations/
        S1.json
        S2.json
        MDE.json
        ...
"""

from __future__ import annotations

import json
import logging
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from langchain_core.messages import AIMessage, BaseMessage, HumanMessage, SystemMessage, ToolMessage

from core.config import settings

logger = logging.getLogger(__name__)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.isoformat()


@dataclass
class TokenUsage:
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0

    def add(self, other: "TokenUsage") -> "TokenUsage":
        self.prompt_tokens += other.prompt_tokens
        self.completion_tokens += other.completion_tokens
        self.total_tokens += other.total_tokens
        return self

    def as_dict(self) -> dict[str, int]:
        return asdict(self)

    @classmethod
    def from_mapping(cls, data: Optional[dict[str, Any]]) -> "TokenUsage":
        if not data:
            return cls()
        prompt = int(
            data.get("prompt_tokens")
            or data.get("input_tokens")
            or data.get("prompt_token_count")
            or 0
        )
        completion = int(
            data.get("completion_tokens")
            or data.get("output_tokens")
            or data.get("completion_token_count")
            or 0
        )
        total = int(data.get("total_tokens") or 0) or (prompt + completion)
        return cls(prompt_tokens=prompt, completion_tokens=completion, total_tokens=total)


def usage_from_ai_message(message: AIMessage) -> TokenUsage:
    """Pull token counts from a LangChain AIMessage (provider-agnostic)."""
    meta = getattr(message, "usage_metadata", None)
    if isinstance(meta, dict) and meta:
        return TokenUsage.from_mapping(meta)

    response = getattr(message, "response_metadata", None) or {}
    if isinstance(response, dict):
        nested = response.get("token_usage") or response.get("usage") or response.get("tokenUsage")
        if nested:
            return TokenUsage.from_mapping(nested)
    return TokenUsage()


def usage_from_openai_completion(completion: Any) -> TokenUsage:
    """Pull token counts from an OpenAI-style completion object."""
    usage = getattr(completion, "usage", None)
    if usage is None:
        return TokenUsage()
    if isinstance(usage, dict):
        return TokenUsage.from_mapping(usage)
    return TokenUsage(
        prompt_tokens=int(getattr(usage, "prompt_tokens", 0) or 0),
        completion_tokens=int(getattr(usage, "completion_tokens", 0) or 0),
        total_tokens=int(getattr(usage, "total_tokens", 0) or 0),
    )


def serialize_message(message: BaseMessage) -> dict[str, Any]:
    """Serialize one LangChain message for the conversation log."""
    content = message.content
    if not isinstance(content, str):
        content = str(content)

    if isinstance(message, SystemMessage):
        return {"role": "system", "content": content}
    if isinstance(message, HumanMessage):
        return {"role": "human", "content": content}
    if isinstance(message, ToolMessage):
        entry: dict[str, Any] = {
            "role": "tool",
            "content": content,
            "tool_call_id": getattr(message, "tool_call_id", "") or "",
        }
        name = getattr(message, "name", None)
        if name:
            entry["name"] = name
        return entry
    if isinstance(message, AIMessage):
        entry = {"role": "ai", "content": content}
        tool_calls = getattr(message, "tool_calls", None) or []
        if tool_calls:
            entry["tool_calls"] = [
                {
                    "id": tc.get("id", ""),
                    "name": tc.get("name", ""),
                    "args": tc.get("args", {}),
                }
                for tc in tool_calls
            ]
        usage = usage_from_ai_message(message)
        if usage.total_tokens or usage.prompt_tokens or usage.completion_tokens:
            entry["usage"] = usage.as_dict()
        return entry

    return {"role": getattr(message, "type", message.__class__.__name__), "content": content}


@dataclass
class SkillTelemetry:
    skill: str
    started_at: str
    finished_at: str
    duration_seconds: float
    token_usage: dict[str, int]
    llm_calls: int
    conversation: str
    status: str
    error: Optional[str] = None

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


class SkillRecorder:
    """Accumulates one skill/probe's conversation and usage, then writes it."""

    def __init__(self, session: "ScanSession", skill: str) -> None:
        self.session = session
        self.skill = skill
        self._t0 = time.perf_counter()
        self.started_at = _utc_now()
        self.usage = TokenUsage()
        self.llm_calls = 0
        self.messages: list[dict[str, Any]] = []
        self.status = "ok"
        self.error: Optional[str] = None

    def record_messages(self, messages: list[BaseMessage]) -> None:
        """Replace the transcript with the full agent message list and sum usage."""
        self.messages = [serialize_message(m) for m in messages]
        self.usage = TokenUsage()
        self.llm_calls = 0
        for message in messages:
            if isinstance(message, AIMessage):
                usage = usage_from_ai_message(message)
                if usage.prompt_tokens or usage.completion_tokens or usage.total_tokens:
                    self.usage.add(usage)
                    self.llm_calls += 1
                else:
                    # Still count the model turn even when the provider omitted usage.
                    self.llm_calls += 1

    def record_structured_turn(
        self,
        *,
        system: str,
        user: str,
        assistant: str,
        usage: Optional[TokenUsage] = None,
    ) -> None:
        """Record a non-tool structured LLM call (e.g. CVSS adjudication)."""
        self.messages = [
            {"role": "system", "content": system},
            {"role": "human", "content": user},
            {"role": "ai", "content": assistant},
        ]
        if usage:
            self.usage.add(usage)
            if usage.total_tokens or usage.prompt_tokens or usage.completion_tokens:
                self.messages[-1]["usage"] = usage.as_dict()
        self.llm_calls += 1

    def finish(self, status: str = "ok", error: Optional[str] = None) -> SkillTelemetry:
        self.status = status
        self.error = error
        finished_at = _utc_now()
        duration = round(time.perf_counter() - self._t0, 3)
        rel = f"conversations/{self.skill}.json"
        path = self.session.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "skill": self.skill,
            "started_at": _iso(self.started_at),
            "finished_at": _iso(finished_at),
            "duration_seconds": duration,
            "status": self.status,
            "error": self.error,
            "token_usage": self.usage.as_dict(),
            "llm_calls": self.llm_calls,
            "messages": self.messages,
        }
        path.write_text(json.dumps(payload, indent=2, default=str) + "\n", encoding="utf-8")
        logger.info(
            "[%s] skill=%s status=%s tokens=%s duration=%.3ss calls=%s",
            self.session.scan_id,
            self.skill,
            self.status,
            self.usage.total_tokens,
            duration,
            self.llm_calls,
        )
        telemetry = SkillTelemetry(
            skill=self.skill,
            started_at=_iso(self.started_at),
            finished_at=_iso(finished_at),
            duration_seconds=duration,
            token_usage=self.usage.as_dict(),
            llm_calls=self.llm_calls,
            conversation=rel,
            status=self.status,
            error=self.error,
        )
        self.session._register_skill(telemetry)
        return telemetry


class ScanSession:
    """Owns one scan's output directory, skill records, and metadata.json."""

    def __init__(
        self,
        *,
        scan_id: str,
        root: Path,
        cve_id: str,
        component_purl: str = "",
        codebase_path: str = "",
        extra: Optional[dict[str, Any]] = None,
    ) -> None:
        self.scan_id = scan_id
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        (self.root / "conversations").mkdir(exist_ok=True)

        self.cve_id = cve_id
        self.component_purl = component_purl
        self.codebase_path = codebase_path
        self.extra = dict(extra or {})
        self.started_at = _utc_now()
        self._t0 = time.perf_counter()
        self._skills: dict[str, SkillTelemetry] = {}
        self.metadata_path = self.root / "metadata.json"
        self.report_path = self.root / "report.json"

    @classmethod
    def create(
        cls,
        *,
        cve_id: str,
        component_purl: str = "",
        codebase_path: str = "",
        scan_id: Optional[str] = None,
        output_dir: Optional[Path] = None,
        output_root: Optional[Path] = None,
        extra: Optional[dict[str, Any]] = None,
    ) -> "ScanSession":
        """Create a session.

        Artefacts land in `output_root` when set; otherwise under
        `{output_dir or settings.scan_output_dir}/{scan_id}/`.
        """
        resolved_id = scan_id or str(uuid.uuid4())
        root = (
            Path(output_root)
            if output_root is not None
            else Path(output_dir or settings.scan_output_dir) / resolved_id
        )
        return cls(
            scan_id=resolved_id,
            root=root,
            cve_id=cve_id,
            component_purl=component_purl,
            codebase_path=codebase_path,
            extra=extra,
        )

    def begin_skill(self, skill: str) -> SkillRecorder:
        return SkillRecorder(self, skill)

    def _register_skill(self, telemetry: SkillTelemetry) -> None:
        self._skills[telemetry.skill] = telemetry

    @property
    def total_usage(self) -> TokenUsage:
        total = TokenUsage()
        for skill in self._skills.values():
            total.add(TokenUsage.from_mapping(skill.token_usage))
        return total

    def finish(
        self,
        *,
        status: str = "completed",
        error: Optional[str] = None,
        report: Any = None,
        plan: Any = None,
    ) -> Path:
        finished_at = _utc_now()
        duration = round(time.perf_counter() - self._t0, 3)
        total = self.total_usage

        if report is not None:
            self.report_path.write_text(
                json.dumps(report.model_dump(mode="json"), indent=2, default=str) + "\n",
                encoding="utf-8",
            )

        metadata = {
            "scan_id": self.scan_id,
            "cve_id": self.cve_id,
            "component_purl": self.component_purl,
            "codebase_path": self.codebase_path,
            "started_at": _iso(self.started_at),
            "finished_at": _iso(finished_at),
            "duration_seconds": duration,
            "status": status,
            "error": error,
            "token_usage": total.as_dict(),
            "token_usage_per_skill": {
                name: {
                    **skill.token_usage,
                    "duration_seconds": skill.duration_seconds,
                    "llm_calls": skill.llm_calls,
                    "status": skill.status,
                    "conversation": skill.conversation,
                    "error": skill.error,
                }
                for name, skill in self._skills.items()
            },
            "skills": [skill.as_dict() for skill in self._skills.values()],
            "plan": plan.model_dump(mode="json") if plan is not None and hasattr(plan, "model_dump") else plan,
            "report": "report.json" if report is not None else None,
            **self.extra,
        }
        self.metadata_path.write_text(json.dumps(metadata, indent=2, default=str) + "\n", encoding="utf-8")
        logger.info(
            "[%s] scan %s: duration=%.3ss total_tokens=%s skills=%s",
            self.scan_id,
            status,
            duration,
            total.total_tokens,
            list(self._skills),
        )
        return self.metadata_path
