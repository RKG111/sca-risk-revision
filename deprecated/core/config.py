"""
The single source of configuration truth.

Everything that used to be duplicated across .env, mcp_servers.json, stack.sh,
joern-run.sh and the vendored mcp_settings.json is derived from this object.
Shell scripts read the same .env; generated JSON is produced by
`python -m core.config` so it can never drift.
"""

from __future__ import annotations

import json
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

ROOT = Path(__file__).resolve().parents[1]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # ── LLM (the only brain; probes and CVSS adjudication both use it) ────────
    llm_provider: str = "ollama"  # ollama | llmas
    llm_model: str = ""  # empty = provider default
    llm_temperature: float = 0.0
    llm_max_iterations: int = 12

    ollama_base_url: str = "http://localhost:11434/v1"
    ollama_api_key: str = "ollama"
    ollama_model: str = "qwen2.5-coder:14b"

    llmas_base_url: str = "https://your-llmas-endpoint/v1"
    llmas_api_key: str = "changeme"
    llmas_model: str = "claude-sonnet-4-5"

    # ── Joern CPG server ─────────────────────────────────────────────────────
    joern_host: str = "127.0.0.1"
    joern_port: int = 16162
    joern_auth_username: str = "user"
    joern_auth_password: str = "password"
    joern_timeout_seconds: int = 300
    # Unused with native Joern (absolute host paths). Kept for env compatibility.
    joern_workspace_path: str = ""
    # Optional override for the joern binary (else PATH).
    joern_bin: str = ""
    joern_xmx: str = "4G"

    # ── mcp-joern (FastMCP SSE in front of Joern) ────────────────────────────
    mcp_joern_host: str = "127.0.0.1"
    mcp_joern_port: int = 8001
    mcp_joern_sse_path: str = "/sse"

    # ── Paths ────────────────────────────────────────────────────────────────
    blueprint_store_path: str = "./blueprints"
    codebase_root: str = "."
    # Per-scan artefacts: metadata.json, report.json, conversations/*.json
    scan_output_dir: str = "./runs"

    # ── API ──────────────────────────────────────────────────────────────────
    api_host: str = "127.0.0.1"
    api_port: int = 8000
    log_level: str = "info"

    @property
    def llm_base_url(self) -> str:
        return self.llmas_base_url if self.llm_provider == "llmas" else self.ollama_base_url

    @property
    def llm_api_key(self) -> str:
        return self.llmas_api_key if self.llm_provider == "llmas" else self.ollama_api_key

    @property
    def resolved_llm_model(self) -> str:
        if self.llm_model:
            return self.llm_model
        return self.llmas_model if self.llm_provider == "llmas" else self.ollama_model

    @property
    def joern_base_url(self) -> str:
        return f"http://{self.joern_host}:{self.joern_port}"

    @property
    def mcp_joern_url(self) -> str:
        return f"http://{self.mcp_joern_host}:{self.mcp_joern_port}{self.mcp_joern_sse_path}"


settings = Settings()


# ─────────────────────────────────────────────────────────────────────────────
# Generated artefacts — so external tools cannot drift from Settings
# ─────────────────────────────────────────────────────────────────────────────

_MCP_JOERN_DIR = ROOT / "third_party" / "mcp-joern"


def mcp_servers_document() -> dict:
    """The MCP registry, derived from Settings rather than hand-maintained."""
    return {
        "_generated_by": "python -m core.config",
        "servers": {
            "joern": {
                "enabled": True,
                "url": settings.mcp_joern_url,
                "stdio": {
                    "command": "uv",
                    "args": ["--directory", str(_MCP_JOERN_DIR), "run", "server.py"],
                    "cwd": str(_MCP_JOERN_DIR),
                    "env": {
                        "HOST": settings.joern_host,
                        "PORT": str(settings.joern_port),
                        "USER_NAME": settings.joern_auth_username,
                        "PASSWORD": settings.joern_auth_password,
                    },
                },
            }
        },
    }


def write_generated_config() -> list[Path]:
    """Regenerate every file that mirrors Settings. Returns what changed."""
    written = []

    servers_path = ROOT / "mcp_servers.json"
    servers_path.write_text(json.dumps(mcp_servers_document(), indent=2) + "\n", encoding="utf-8")
    written.append(servers_path)

    if _MCP_JOERN_DIR.is_dir():
        settings_path = _MCP_JOERN_DIR / "mcp_settings.json"
        # Shape expected by third_party/mcp-joern/server.py::load_server_config
        settings_path.write_text(
            json.dumps(
                {
                    "_generated_by": "python -m core.config",
                    "mcpServers": {
                        "joern": {
                            "config": {
                                "host": settings.joern_host,
                                "port": str(settings.joern_port),
                                "log_level": "ERROR",
                                "timeout": str(settings.joern_timeout_seconds),
                                "username": settings.joern_auth_username,
                                "password": settings.joern_auth_password,
                                "description": "Joern mcp server",
                            }
                        }
                    },
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        written.append(settings_path)

    return written


if __name__ == "__main__":
    for path in write_generated_config():
        print(f"wrote {path.relative_to(ROOT)}")
