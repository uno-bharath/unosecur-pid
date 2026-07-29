#!/usr/bin/env bash

set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

require_command docker
require_command curl
load_environment

info "Infrastructure"
compose ps

printf '\n'
if check_postgres; then
  success "PostgreSQL is ready."
else
  warn "PostgreSQL is unavailable."
fi

if curl --silent --fail --max-time 2 "http://localhost:${API_PORT:-4000}/api/health" >/dev/null 2>&1; then
  success "PID API is ready."
else
  warn "PID API is not running."
fi

if curl --silent --fail --max-time 2 "http://localhost:3000" >/dev/null 2>&1; then
  success "PID dashboard is ready."
else
  warn "PID dashboard is not running."
fi

if curl --silent --fail --max-time 2 "${OLLAMA_BASE_URL:-http://127.0.0.1:11434}/api/tags" >/dev/null 2>&1; then
  success "Ollama is ready."
else
  warn "Ollama is unavailable; deterministic Copilot fallback will be used."
fi
