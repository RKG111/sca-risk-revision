"""Application settings for the Risk Assessment Agent (v2)."""

from __future__ import annotations

from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

# Repository root (parent of app/)
ROOT_DIR = Path(__file__).resolve().parent.parent
WORKSPACE_DIR = ROOT_DIR / "workspace"
SKILLS_DIR = ROOT_DIR / "skills"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # LLM — Ollama OpenAI-compatible endpoint
    llm_base_url: str = "http://localhost:11434/v1"
    llm_api_key: str = "ollama"
    llm_model: str = "qwen2.5-coder:14b"
    llm_temperature: float = 0.1

    # Paths
    workspace_dir: Path = WORKSPACE_DIR
    skills_dir: Path = SKILLS_DIR

    log_level: str = "INFO"


settings = Settings()
