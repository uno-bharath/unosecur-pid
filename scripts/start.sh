#!/usr/bin/env bash

set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

require_command pnpm
require_command docker
require_command curl
load_environment

if ! docker info >/dev/null 2>&1; then
  fail "Docker is not running. Start Docker Desktop and retry."
fi

info "Starting Redis and Neo4j."
compose up --detach --wait

if ! check_postgres; then
  fail "PostgreSQL is unavailable. Run './scripts/pid.sh setup' for diagnostics."
fi

if ! curl --silent --fail --max-time 2 "${OLLAMA_BASE_URL:-http://127.0.0.1:11434}/api/tags" >/dev/null 2>&1; then
  warn "Ollama is unavailable; Copilot will use its deterministic evidence fallback."
fi

success "Starting UnoSecur PID."
info "Dashboard: http://localhost:3000"
info "API:       http://localhost:${API_PORT:-4000}/api"
info "Swagger:   http://localhost:${API_PORT:-4000}/docs"
info "Press Ctrl+C to stop the API and dashboard."

cd "${PROJECT_ROOT}"
exec pnpm dev
