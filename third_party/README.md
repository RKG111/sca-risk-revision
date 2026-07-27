# Vendored / cloned third-party tools

## mcp-joern (sfncat)

Open-source Joern MCP: https://github.com/sfncat/mcp-joern

**Role in this product:** FastMCP tool backend for the **standalone Qwen S1 agent**.
Not used via Cursor.

### Preferred: FastMCP SSE (stack-managed)

`./scripts/stack.sh start` launches:

```text
third_party/mcp-joern/.venv/bin/python scripts/run_mcp_joern_sse.py
```

as a long-lived HTTP SSE service on `MCP_JOERN_PORT` (default **8001**).
Joern JVM stays on **16162**. S1 connects to `http://127.0.0.1:8001/sse`.

### Fallback: stdio

If SSE is down, the skill runner can still spawn:

```text
uv --directory third_party/mcp-joern run server.py
```

as a short-lived stdio MCP subprocess.

- Product app: root `.venv`
- mcp-joern: its own uv `.venv` (created by `uv sync`) — do not activate it for the app
- Joern JVM must already be up (`./scripts/stack.sh start`)

```bash
# refresh clone
git -C third_party/mcp-joern pull

# ensure mcp-joern deps (once)
cd third_party/mcp-joern && uv sync
```
