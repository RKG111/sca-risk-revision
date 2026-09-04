"""File-based workspace helpers for scan state under workspace/{scan_id}/."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from app.config import settings


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def scan_dir(scan_id: str) -> Path:
    return settings.workspace_dir / scan_id


def conversations_dir(scan_id: str) -> Path:
    return scan_dir(scan_id) / "conversations"


def create_workspace(scan_id: str) -> Path:
    """Create workspace/{scan_id}/ and conversations/ subfolder."""
    root = scan_dir(scan_id)
    conversations_dir(scan_id).mkdir(parents=True, exist_ok=True)
    return root


def write_json(scan_id: str, filename: str, data: Any) -> Path:
    path = scan_dir(scan_id) / filename
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, default=str) + "\n", encoding="utf-8")
    return path


def read_json(scan_id: str, filename: str) -> Optional[dict[str, Any]]:
    """Return parsed JSON, or None if the file is missing or unreadable."""
    path = scan_dir(scan_id) / filename
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None


def list_scan_ids() -> list[str]:
    root = settings.workspace_dir
    if not root.is_dir():
        return []
    return sorted(p.name for p in root.iterdir() if p.is_dir() and not p.name.startswith("."))


def write_conversation(scan_id: str, name: str, messages: list[dict[str, Any]]) -> Path:
    """Persist a raw LLM conversation log under conversations/."""
    path = conversations_dir(scan_id) / f"{name}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(messages, indent=2, default=str) + "\n", encoding="utf-8")
    return path


def update_status(
    scan_id: str,
    status: str,
    *,
    step: Optional[str] = None,
    error: Optional[str] = None,
    extra: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """Merge updates into status.json."""
    current = read_json(scan_id, "status.json") or {}
    current["scan_id"] = scan_id
    current["status"] = status
    current["updated_at"] = utc_now_iso()
    if step is not None:
        current["current_step"] = step
    if error is not None:
        current["error"] = error
    if extra:
        current.update(extra)
    write_json(scan_id, "status.json", current)
    return current
