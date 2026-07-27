#!/usr/bin/env bash
# Standalone product stack: Ollama + Joern + mcp-joern (FastMCP SSE) + FastAPI
#
# Usage:
#   ./scripts/stack.sh start
#   ./scripts/stack.sh stop
#   ./scripts/stack.sh status
#   ./scripts/stack.sh logs
#
# mcp-joern runs as FastMCP SSE HTTP (default :8001) so Qwen connects over HTTP.
# Joern JVM remains on :16162.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

RUN_DIR="${ROOT}/.run"
mkdir -p "$RUN_DIR"

if [[ -f "${ROOT}/.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "${ROOT}/.env"
  set +a
fi

API_HOST="${API_HOST:-0.0.0.0}"
API_PORT="${API_PORT:-8000}"
JOERN_HOST="${JOERN_HOST:-127.0.0.1}"
JOERN_PORT="${JOERN_PORT:-16162}"
JOERN_AUTH_USERNAME="${JOERN_AUTH_USERNAME:-user}"
JOERN_AUTH_PASSWORD="${JOERN_AUTH_PASSWORD:-password}"
MCP_JOERN_HOST="${MCP_JOERN_HOST:-127.0.0.1}"
MCP_JOERN_PORT="${MCP_JOERN_PORT:-8001}"
OLLAMA_HOST="${OLLAMA_HOST:-127.0.0.1}"
OLLAMA_PORT="${OLLAMA_PORT:-11434}"
OLLAMA_MODEL="${OLLAMA_MODEL:-qwen2.5-coder:14b}"
STACK_STOP_OLLAMA="${STACK_STOP_OLLAMA:-0}"
JOERN_WAIT_SECS="${JOERN_WAIT_SECS:-90}"
OLLAMA_WAIT_SECS="${OLLAMA_WAIT_SECS:-60}"

API_PID_FILE="${RUN_DIR}/api.pid"
API_LOG_FILE="${RUN_DIR}/api.log"
OLLAMA_PID_FILE="${RUN_DIR}/ollama.pid"
OLLAMA_LOG_FILE="${RUN_DIR}/ollama.log"
MCP_PID_FILE="${RUN_DIR}/mcp_joern.pid"
MCP_LOG_FILE="${RUN_DIR}/mcp_joern.log"

log() { echo "[stack] $*"; }
ok()  { echo "[stack] OK  $*"; }
bad() { echo "[stack] FAIL $*"; }

require_docker() {
  if docker info >/dev/null 2>&1; then
    return 0
  fi
  bad "cannot talk to Docker"
  if [[ -S /var/run/docker.sock ]]; then
    echo "  Docker is running but this shell cannot access it."
    if getent group docker 2>/dev/null | grep -qE "(^|:)${USER}(,|$)"; then
      echo "  You are in the docker group, but this shell needs a refresh:"
      echo "    newgrp docker"
      echo "    # or: sg docker -c './scripts/stack.sh start'"
    else
      echo "  Fix (one-time): sudo usermod -aG docker \"\$USER\" && newgrp docker"
    fi
  else
    echo "  Start the Docker daemon first."
  fi
  exit 1
}

ollama_base() {
  echo "http://${OLLAMA_HOST}:${OLLAMA_PORT}"
}

ollama_ready() {
  curl -sf "$(ollama_base)/api/tags" >/dev/null 2>&1
}

ensure_ollama() {
  if ollama_ready; then
    ok "Ollama already up at $(ollama_base)"
  else
    log "Ollama down — starting..."
    if command -v systemctl >/dev/null 2>&1 && systemctl is-enabled ollama >/dev/null 2>&1; then
      if systemctl start ollama 2>/dev/null; then
        log "started via systemctl"
      elif systemctl --user start ollama 2>/dev/null; then
        log "started via systemctl --user"
      else
        _start_ollama_serve
      fi
    else
      _start_ollama_serve
    fi

    local i=0
    while (( i < OLLAMA_WAIT_SECS )); do
      if ollama_ready; then
        ok "Ollama ready"
        break
      fi
      sleep 1
      ((i++)) || true
    done
    if ! ollama_ready; then
      bad "Ollama did not become ready within ${OLLAMA_WAIT_SECS}s"
      exit 1
    fi
  fi

  ensure_ollama_model
}

_start_ollama_serve() {
  if ! command -v ollama >/dev/null 2>&1; then
    bad "ollama binary not found in PATH"
    exit 1
  fi
  nohup ollama serve >"${OLLAMA_LOG_FILE}" 2>&1 &
  echo $! >"${OLLAMA_PID_FILE}"
  log "ollama serve pid=$(cat "${OLLAMA_PID_FILE}") log=${OLLAMA_LOG_FILE}"
}

ensure_ollama_model() {
  local model="${OLLAMA_MODEL}"
  if ollama list 2>/dev/null | grep -qF "${model}"; then
    ok "model present: ${model}"
    return 0
  fi
  log "pulling model ${model} (may take a while)..."
  ollama pull "${model}"
  ok "model ready: ${model}"
}

joern_ready() {
  curl -sf -u "${JOERN_AUTH_USERNAME}:${JOERN_AUTH_PASSWORD}" \
    -H 'Content-Type: application/json' \
    -d '{"query":"version"}' \
    "http://${JOERN_HOST}:${JOERN_PORT}/query-sync" >/dev/null 2>&1
}

ensure_joern() {
  require_docker
  if joern_ready; then
    ok "Joern already up at ${JOERN_HOST}:${JOERN_PORT}"
    return 0
  fi
  log "starting Joern via ./joern-run.sh --detach"
  "${ROOT}/joern-run.sh" --detach
  local i=0
  while (( i < JOERN_WAIT_SECS )); do
    if joern_ready; then
      ok "Joern ready"
      return 0
    fi
    sleep 2
    ((i+=2)) || true
  done
  bad "Joern did not become ready within ${JOERN_WAIT_SECS}s"
  echo "  Check: docker logs sca-joern"
  exit 1
}

mcp_joern_ready() {
  # FastMCP SSE endpoint responds when the server is up (often 200 with event-stream).
  local code
  code="$(curl -s -o /dev/null -w "%{http_code}" \
    --max-time 2 \
    -H "Accept: text/event-stream" \
    "http://${MCP_JOERN_HOST}:${MCP_JOERN_PORT}/sse" 2>/dev/null || true)"
  [[ "${code}" =~ ^(200|301|302|307|405|406)$ ]]
}

ensure_mcp_joern() {
  if mcp_joern_ready; then
    ok "mcp-joern FastMCP SSE already up at http://${MCP_JOERN_HOST}:${MCP_JOERN_PORT}/sse"
    return 0
  fi

  local runner_py="${ROOT}/third_party/mcp-joern/.venv/bin/python"
  if [[ ! -x "${runner_py}" ]]; then
    if command -v uv >/dev/null 2>&1; then
      log "bootstrapping mcp-joern venv (uv sync)"
      (cd "${ROOT}/third_party/mcp-joern" && uv sync)
    else
      bad "third_party/mcp-joern/.venv missing and uv not installed"
      exit 1
    fi
  fi

  log "starting mcp-joern FastMCP SSE on ${MCP_JOERN_HOST}:${MCP_JOERN_PORT}"
  export JOERN_AUTH_USERNAME JOERN_AUTH_PASSWORD
  export MCP_JOERN_HOST MCP_JOERN_PORT
  nohup "${runner_py}" "${ROOT}/scripts/run_mcp_joern_sse.py" \
    >"${MCP_LOG_FILE}" 2>&1 &
  echo $! >"${MCP_PID_FILE}"

  local i=0
  while (( i < 45 )); do
    if mcp_joern_ready; then
      ok "mcp-joern SSE ready pid=$(cat "${MCP_PID_FILE}")"
      return 0
    fi
    sleep 1
    ((i++)) || true
  done
  bad "mcp-joern SSE did not become ready — see ${MCP_LOG_FILE}"
  exit 1
}

api_running() {
  if [[ -f "${API_PID_FILE}" ]]; then
    local pid
    pid="$(cat "${API_PID_FILE}")"
    if kill -0 "${pid}" 2>/dev/null; then
      return 0
    fi
  fi
  return 1
}

ensure_api() {
  if api_running; then
    ok "API already running pid=$(cat "${API_PID_FILE}")"
    return 0
  fi

  local uvicorn_bin="${ROOT}/.venv/bin/uvicorn"
  if [[ ! -x "${uvicorn_bin}" ]]; then
    bad "uvicorn not found at ${uvicorn_bin} — run: pip install -r requirements.txt"
    exit 1
  fi

  export LLM_PROVIDER="${LLM_PROVIDER:-ollama}"
  export CODEBASE_ROOT="${CODEBASE_ROOT:-.}"
  export MCP_JOERN_HOST MCP_JOERN_PORT
  export PYTHONPATH="${ROOT}${PYTHONPATH:+:$PYTHONPATH}"

  log "starting API on ${API_HOST}:${API_PORT}"
  nohup "${uvicorn_bin}" api.main:app \
    --host "${API_HOST}" \
    --port "${API_PORT}" \
    >"${API_LOG_FILE}" 2>&1 &
  echo $! >"${API_PID_FILE}"

  local i=0
  while (( i < 30 )); do
    if curl -sf "http://127.0.0.1:${API_PORT}/health" >/dev/null 2>&1; then
      ok "API ready pid=$(cat "${API_PID_FILE}")"
      return 0
    fi
    sleep 1
    ((i++)) || true
  done
  bad "API did not become ready — see ${API_LOG_FILE}"
  exit 1
}

_stop_pidfile() {
  local name="$1"
  local pidfile="$2"
  if [[ -f "${pidfile}" ]]; then
    local pid
    pid="$(cat "${pidfile}")"
    if kill -0 "${pid}" 2>/dev/null; then
      kill "${pid}" 2>/dev/null || true
      sleep 1
      kill -9 "${pid}" 2>/dev/null || true
      ok "stopped ${name} pid=${pid}"
    fi
    rm -f "${pidfile}"
  else
    log "${name} pid file absent"
  fi
}

cmd_start() {
  log "starting stack (Ollama + Joern + mcp-joern FastMCP SSE + API)"
  ensure_ollama
  ensure_joern
  ensure_mcp_joern
  ensure_api
  log "stack up. Try: ./scripts/stack.sh status"
}

cmd_stop() {
  log "stopping stack"
  _stop_pidfile "API" "${API_PID_FILE}"
  _stop_pidfile "mcp-joern" "${MCP_PID_FILE}"

  if [[ -x "${ROOT}/joern-run.sh" ]]; then
    "${ROOT}/joern-run.sh" --stop || true
  fi

  if [[ "${STACK_STOP_OLLAMA}" == "1" ]]; then
    _stop_pidfile "ollama" "${OLLAMA_PID_FILE}"
  else
    log "leaving Ollama running (set STACK_STOP_OLLAMA=1 to stop ollama serve we started)"
  fi

  ok "stack stopped"
}

cmd_status() {
  echo "=== stack status ==="

  if docker info >/dev/null 2>&1; then
    ok "docker"
  else
    bad "docker"
  fi

  if joern_ready; then
    ok "joern     http://${JOERN_HOST}:${JOERN_PORT}/query-sync"
  else
    bad "joern     http://${JOERN_HOST}:${JOERN_PORT}/query-sync"
  fi

  if mcp_joern_ready; then
    ok "mcp-joern http://${MCP_JOERN_HOST}:${MCP_JOERN_PORT}/sse (FastMCP)"
  else
    bad "mcp-joern http://${MCP_JOERN_HOST}:${MCP_JOERN_PORT}/sse"
  fi

  if ollama_ready; then
    ok "ollama    $(ollama_base) model=${OLLAMA_MODEL}"
  else
    bad "ollama    $(ollama_base)"
  fi

  if curl -sf "http://127.0.0.1:${API_PORT}/health" >/dev/null 2>&1; then
    ok "api       http://127.0.0.1:${API_PORT}/health"
  else
    bad "api       http://127.0.0.1:${API_PORT}/health"
  fi
}

cmd_logs() {
  echo "=== API log (${API_LOG_FILE}) ==="
  tail -n 40 "${API_LOG_FILE}" 2>/dev/null || echo "(no api log)"
  echo
  echo "=== mcp-joern log (${MCP_LOG_FILE}) ==="
  tail -n 40 "${MCP_LOG_FILE}" 2>/dev/null || echo "(no mcp-joern log)"
  echo
  echo "=== Joern container logs ==="
  docker logs --tail 40 sca-joern 2>/dev/null || echo "(no sca-joern container)"
  if [[ -f "${OLLAMA_LOG_FILE}" ]]; then
    echo
    echo "=== Ollama log (${OLLAMA_LOG_FILE}) ==="
    tail -n 20 "${OLLAMA_LOG_FILE}" 2>/dev/null || true
  fi
}

usage() {
  cat <<EOF
Usage: $0 {start|stop|status|logs}

  start   Ollama + Joern + mcp-joern (FastMCP SSE) + API
  stop    Stop API + mcp-joern + Joern (Ollama kept unless STACK_STOP_OLLAMA=1)
  status  Health checks
  logs    Tail service logs
EOF
}

main() {
  local cmd="${1:-}"

  # If docker group is configured but not active in this shell, re-exec under sg.
  if [[ "${STACK_DOCKER_SG:-}" != "1" ]] \
     && ! docker info >/dev/null 2>&1 \
     && getent group docker 2>/dev/null | grep -qE "(^|:)${USER}(,|$)" \
     && sg docker -c 'docker info' >/dev/null 2>&1; then
    log "docker group inactive in this shell — re-exec via sg docker"
    exec env STACK_DOCKER_SG=1 sg docker -c "\"$0\" $*"
  fi

  case "${cmd}" in
    start)  cmd_start ;;
    stop)   cmd_stop ;;
    status) cmd_status ;;
    logs)   cmd_logs ;;
    *)      usage; exit 1 ;;
  esac
}

main "$@"
