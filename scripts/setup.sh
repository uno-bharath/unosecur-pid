#!/usr/bin/env bash

set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

info "Preparing UnoSecur PID."

require_command node
require_command pnpm
require_command docker
require_command curl
require_command pg_isready

if ! docker info >/dev/null 2>&1; then
  fail "Docker is not running. Start Docker Desktop and retry."
fi

if [[ ! -f "${PROJECT_ROOT}/.env" ]]; then
  cp "${PROJECT_ROOT}/.env.example" "${PROJECT_ROOT}/.env"
  success "Created .env from .env.example."
else
  info "Using the existing .env."
fi

load_environment

info "Installing workspace dependencies."
(
  cd "${PROJECT_ROOT}"
  pnpm install --frozen-lockfile
)

info "Starting Redis and Neo4j."
compose up --detach --wait

if ! check_postgres; then
  fail "PostgreSQL is unavailable for DATABASE_URL='${DATABASE_URL}'. Start the existing PID database and verify its credentials."
fi
success "PostgreSQL is ready."

info "Generating Prisma Client and applying committed migrations."
(
  cd "${PROJECT_ROOT}"
  pnpm --filter @unosecur/api prisma:generate
  pnpm --filter @unosecur/api exec prisma migrate deploy
  pnpm --filter @unosecur/api prisma:seed
)

if wait_for_url "Ollama" "${OLLAMA_BASE_URL:-http://127.0.0.1:11434}/api/tags" 2 1; then
  info "Ollama model configured as '${OLLAMA_MODEL:-not set}'."
else
  warn "Ollama is not running. The deterministic fallback remains available, but local AI responses require 'ollama serve'."
fi

success "Setup complete. Run './scripts/pid.sh start'."
