"""Skill discovery from Markdown files with YAML frontmatter."""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from app.config import settings

logger = logging.getLogger(__name__)

FRONTMATTER_RE = re.compile(r"\A---\s*\n(.*?)\n---\s*\n(.*)\Z", re.DOTALL)


@dataclass
class Skill:
    id: str
    name: str
    description: str
    depends_on: list[str] = field(default_factory=list)
    tools: list[str] = field(default_factory=list)
    output_file: str = ""
    body: str = ""
    path: Optional[Path] = None
    meta: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "depends_on": self.depends_on,
            "tools": self.tools,
            "output_file": self.output_file,
            "path": str(self.path) if self.path else None,
            "meta": self.meta,
        }


def _parse_frontmatter(raw: str) -> tuple[dict[str, Any], str]:
    """Minimal YAML frontmatter parser (no PyYAML dependency required for stubs)."""
    match = FRONTMATTER_RE.match(raw)
    if not match:
        return {}, raw

    meta: dict[str, Any] = {}
    body = match.group(2)
    for line in match.group(1).splitlines():
        line = line.strip()
        if not line or line.startswith("#") or ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if value.startswith("[") and value.endswith("]"):
            inner = value[1:-1].strip()
            meta[key] = (
                [item.strip().strip('"').strip("'") for item in inner.split(",") if item.strip()]
                if inner
                else []
            )
        elif value.lower() in ("true", "false"):
            meta[key] = value.lower() == "true"
        else:
            meta[key] = value
    return meta, body


def load_skills(skills_dir: Optional[Path] = None) -> list[Skill]:
    """Read all ``*.md`` skill definitions from the skills directory."""
    directory = skills_dir or settings.skills_dir
    if not directory.is_dir():
        logger.warning("skills directory missing: %s", directory)
        return []

    skills: list[Skill] = []
    for path in sorted(directory.glob("*.md")):
        try:
            text = path.read_text(encoding="utf-8")
        except OSError as exc:
            logger.warning("could not read skill %s: %s", path, exc)
            continue

        meta, body = _parse_frontmatter(text)
        skill_id = str(meta.get("id") or path.stem)
        skills.append(
            Skill(
                id=skill_id,
                name=str(meta.get("name") or skill_id),
                description=str(meta.get("description") or ""),
                depends_on=list(meta.get("depends_on") or []),
                tools=list(meta.get("tools") or []),
                output_file=str(meta.get("output_file") or f"{skill_id}_output.json"),
                body=body.strip(),
                path=path,
                meta=meta,
            )
        )
    return skills


def order_by_dependencies(skills: list[Skill], selected_ids: list[str]) -> list[Skill]:
    """Topological order of selected skills honoring depends_on."""
    by_id = {s.id: s for s in skills}
    selected = [sid for sid in selected_ids if sid in by_id]
    ordered: list[Skill] = []
    seen: set[str] = set()

    def visit(skill_id: str) -> None:
        if skill_id in seen or skill_id not in by_id:
            return
        skill = by_id[skill_id]
        for dep in skill.depends_on:
            if dep in selected or dep in by_id:
                visit(dep)
        if skill_id not in seen:
            seen.add(skill_id)
            ordered.append(skill)

    for sid in selected:
        visit(sid)
    return ordered
