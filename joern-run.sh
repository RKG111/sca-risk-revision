#!/usr/bin/env bash
# Start a native Joern REST server (mcp-joern compatible).
#
# Requires `joern` on PATH (e.g. /usr/local/bin/joern from /opt/joern).
# Loads third_party/mcp-joern/server_tools.sc.
# Prefer: ./scripts/stack.sh start
#
# Usage:
#   ./joern-run.sh              # foreground
#   ./joern-run.sh --detach     # background (.run/joern.pid)
#   ./joern-run.sh --stop       # stop background server

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUN_DIR="${ROOT}/.run"
mkdir -p "${RUN_DIR}"

if [[ -f "${ROOT}/.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "${ROOT}/.env"
  set +a
fi

JOERN_BIN="${JOERN_BIN:-$(command -v joern || true)}"
PORT="${JOERN_PORT:-16162}"
HOST="${JOERN_HOST:-127.0.0.1}"
USER_NAME="${JOERN_AUTH_USERNAME:-user}"
PASSWORD="${JOERN_AUTH_PASSWORD:-password}"
XMX="${JOERN_XMX:-4G}"
TOOLS_SC="${ROOT}/third_party/mcp-joern/server_tools.sc"
PID_FILE="${RUN_DIR}/joern.pid"
LOG_FILE="${RUN_DIR}/joern.log"
MODE="foreground"

for arg in "$@"; do
  case "$arg" in
    --detach|-d) MODE="detach" ;;
    --stop)
      if [[ -f "${PID_FILE}" ]]; then
        pid="$(cat "${PID_FILE}")"
        if kill -0 "${pid}" 2>/dev/null; then
          # Kill the process group started by setsid (covers the Joern JVM).
          kill -- "-${pid}" 2>/dev/null || kill "${pid}" 2>/dev/null || true
          sleep 2
          kill -9 -- "-${pid}" 2>/dev/null || kill -9 "${pid}" 2>/dev/null || true
          echo "Stopped Joern pid=${pid}"
        else
          echo "Joern pid file present but process ${pid} is not running"
        fi
        rm -f "${PID_FILE}"
      fi
      if command -v fuser >/dev/null 2>&1; then
        fuser -k "${PORT}/tcp" 2>/dev/null || true
      fi
      # Clean up a leftover Docker Joern from older setups (best-effort).
      if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
        docker rm -f "${JOERN_CONTAINER_NAME:-sca-joern}" >/dev/null 2>&1 || true
      fi
      echo "Stopped Joern (if it was running on :${PORT})"
      exit 0
      ;;
    --help|-h)
      echo "Usage: $0 [--detach|--stop]"
      exit 0
      ;;
  esac
done

if [[ -z "${JOERN_BIN}" || ! -x "${JOERN_BIN}" ]]; then
  echo "ERROR: joern binary not found on PATH."
  echo "  Install from https://github.com/joernio/joern/releases (joern-install.sh)"
  echo "  or set JOERN_BIN=/opt/joern/joern-cli/joern"
  exit 1
fi

if [[ ! -f "${TOOLS_SC}" ]]; then
  echo "ERROR: third_party/mcp-joern missing. Clone it:"
  echo "  git clone --depth 1 https://github.com/sfncat/mcp-joern.git third_party/mcp-joern"
  exit 1
fi

# Replace any previous background instance.
if [[ -f "${PID_FILE}" ]]; then
  old="$(cat "${PID_FILE}")"
  if kill -0 "${old}" 2>/dev/null; then
    kill "${old}" 2>/dev/null || true
    sleep 1
    kill -9 "${old}" 2>/dev/null || true
  fi
  rm -f "${PID_FILE}"
fi
# Also drop a leftover Docker Joern so the port is free.
if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
  docker rm -f "${JOERN_CONTAINER_NAME:-sca-joern}" >/dev/null 2>&1 || true
fi

CMD=(
  "${JOERN_BIN}"
  "-J-Xmx${XMX}"
  --server
  --server-host "${HOST}"
  --server-port "${PORT}"
  --server-auth-username "${USER_NAME}"
  --server-auth-password "${PASSWORD}"
  --import "${TOOLS_SC}"
)

echo "Starting native Joern on http://${HOST}:${PORT}"
echo "  binary: ${JOERN_BIN}"
echo "  auth:   ${USER_NAME} / ****"
echo "  scripts:${TOOLS_SC}"
echo "  heap:   -J-Xmx${XMX}"
echo "  health: POST /query-sync  query=version"

export TERM="${TERM:-dumb}"
export SL_LOGGING_LEVEL="${SL_LOGGING_LEVEL:-ERROR}"

if [[ "$MODE" == "detach" ]]; then
  # New session so --stop can tear down the whole JVM tree.
  setsid nohup "${CMD[@]}" >"${LOG_FILE}" 2>&1 &
  echo $! >"${PID_FILE}"
  echo "Detached pid=$(cat "${PID_FILE}") log=${LOG_FILE}"
  echo "Stop with: ./joern-run.sh --stop"
else
  exec "${CMD[@]}"
fi
