#!/usr/bin/env python3
"""
Run sfncat/mcp-joern as a FastMCP SSE HTTP service for the standalone Qwen agent.

Joern JVM stays on JOERN_PORT (default 16162).
This MCP HTTP layer listens on MCP_JOERN_PORT (default 8001).

Usage (normally via ./scripts/stack.sh):
  MCP_JOERN_PORT=8001 python scripts/run_mcp_joern_sse.py
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MCP_DIR = ROOT / "third_party" / "mcp-joern"


def main() -> None:
    if not (MCP_DIR / "server.py").is_file():
        sys.stderr.write(f"mcp-joern not found at {MCP_DIR}\n")
        sys.exit(1)

    os.chdir(MCP_DIR)
    sys.path.insert(0, str(MCP_DIR))

    # Joern JVM endpoint (used by mcp-joern's joern_remote)
    os.environ.setdefault("JOERN_AUTH_USERNAME", os.getenv("JOERN_AUTH_USERNAME", "user"))
    os.environ.setdefault("JOERN_AUTH_PASSWORD", os.getenv("JOERN_AUTH_PASSWORD", "password"))

    host = os.getenv("MCP_JOERN_HOST", "127.0.0.1")
    port = int(os.getenv("MCP_JOERN_PORT", "8001"))

    import server as mcp_server  # noqa: E402  — loads tools via generate()

    mcp_server.joern_mcp.settings.host = host
    mcp_server.joern_mcp.settings.port = port
    print(f"[mcp-joern-sse] FastMCP SSE on http://{host}:{port}{mcp_server.joern_mcp.settings.sse_path}")
    print(f"[mcp-joern-sse] Joern backend: {mcp_server.server_endpoint}")
    mcp_server.joern_mcp.run(transport="sse")


if __name__ == "__main__":
    main()
