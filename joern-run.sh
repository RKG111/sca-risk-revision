#!/usr/bin/env bash
# Start Joern REST server via Docker (mcp-joern compatible).
#
# Repo mounted at /app. Loads third_party/mcp-joern/server_tools.sc.
# Prefer: ./scripts/stack.sh start
#
# Usage:
#   ./joern-run.sh              # foreground
#   ./joern-run.sh --detach     # background
#   ./joern-run.sh --stop       # stop background container

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# GHCR has no :latest — use :nightly (same as :master currently). Override with JOERN_IMAGE.
IMAGE="${JOERN_IMAGE:-ghcr.io/joernio/joern:nightly}"
NAME="${JOERN_CONTAINER_NAME:-sca-joern}"
PORT="${JOERN_PORT:-16162}"
USER_NAME="${JOERN_AUTH_USERNAME:-user}"
PASSWORD="${JOERN_AUTH_PASSWORD:-password}"
TOOLS_SC="/app/third_party/mcp-joern/server_tools.sc"
MODE="foreground"

for arg in "$@"; do
  case "$arg" in
    --detach|-d) MODE="detach" ;;
    --stop)
      docker stop "$NAME" >/dev/null 2>&1 || true
      echo "Stopped $NAME (if it was running)"
      exit 0
      ;;
    --help|-h)
      echo "Usage: $0 [--detach|--stop]"
      exit 0
      ;;
  esac
done

if [[ ! -f "${ROOT}/third_party/mcp-joern/server_tools.sc" ]]; then
  echo "ERROR: third_party/mcp-joern missing. Clone it:"
  echo "  git clone --depth 1 https://github.com/sfncat/mcp-joern.git third_party/mcp-joern"
  exit 1
fi

# Docker must be available on the host
if ! docker info >/dev/null 2>&1; then
  echo "ERROR: cannot talk to Docker daemon."
  echo "  socket: /var/run/docker.sock"
  if [[ -S /var/run/docker.sock ]]; then
    echo "  Docker is running, but this user cannot access it."
    echo "  Fix (one-time):"
    echo "    sudo usermod -aG docker \"\$USER\""
    echo "    newgrp docker   # or log out/in"
    echo "  Then re-run: ./joern-run.sh --detach"
  else
    echo "  Start Docker, then re-run ./joern-run.sh --detach"
  fi
  exit 1
fi

docker rm -f "$NAME" >/dev/null 2>&1 || true

# Joern listens on PORT inside container; publish same port on host for mcp-joern
COMMON=(
  --name "$NAME"
  -p "${PORT}:${PORT}"
  -e TERM=dumb
  -e SL_LOGGING_LEVEL=ERROR
  -v /tmp:/tmp
  -v "${ROOT}:/app:rw"
  -w /app
  "$IMAGE"
  joern
  -J-Xmx4G
  --server
  --server-host 0.0.0.0
  --server-port "${PORT}"
  --server-auth-username "${USER_NAME}"
  --server-auth-password "${PASSWORD}"
  --import "${TOOLS_SC}"
)

echo "Starting Joern (mcp-joern compatible) on http://127.0.0.1:${PORT}"
echo "  repo mounted at: /app"
echo "  auth: ${USER_NAME} / ****"
echo "  scripts: ${TOOLS_SC}"
echo "  health (query-sync): POST /query-sync with query 'version'"

if [[ "$MODE" == "detach" ]]; then
  docker run --rm -d "${COMMON[@]}"
  echo "Detached as container: $NAME"
  echo "Stop with: ./joern-run.sh --stop"
  echo "Wait ~30s for Joern JVM warmup, then:"
  echo "  curl -u ${USER_NAME}:${PASSWORD} -H 'Content-Type: application/json' \\"
  echo "    -d '{\"query\":\"version\"}' http://127.0.0.1:${PORT}/query-sync"
else
  docker run --rm -it "${COMMON[@]}"
fi
