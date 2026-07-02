"""
Central settings — loaded from environment / .env file via pydantic-settings.
Import `settings` wherever config values are needed.
"""

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # ── LLMaS (primary LLM — Claude Sonnet) ──────────────────────────────────
    llmas_base_url: str = "https://your-llmas-endpoint/v1"
    llmas_api_key: str = "changeme"
    llmas_model: str = "claude-sonnet-4-5"

    # ── Local Ollama (GPU VM) ─────────────────────────────────────────────────
    ollama_base_url: str = "http://localhost:11434/v1"
    ollama_api_key: str = "ollama"
    ollama_embed_model: str = "nomic-embed-text"
    ollama_reasoning_model: str = "qwen2.5-coder:32b"

    # ── NVD API ───────────────────────────────────────────────────────────────
    nvd_api_key: str = ""

    # ── Joern ─────────────────────────────────────────────────────────────────
    joern_host: str = "localhost"
    joern_port: int = 8080

    # ── ChromaDB ──────────────────────────────────────────────────────────────
    chromadb_persist_path: str = "./.chromadb"

    # ── Runtime ───────────────────────────────────────────────────────────────
    codebase_root: str = "/codebases"
    log_level: str = "info"

    @property
    def joern_base_url(self) -> str:
        return f"http://{self.joern_host}:{self.joern_port}"


settings = Settings()
