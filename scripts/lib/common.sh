#!/usr/bin/env bash

set -Eeuo pipefail

COMMON_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${COMMON_DIR}/../.." && pwd)"
COMPOSE_FILE="${PROJECT_ROOT}/infrastructure/docker/compose.yml"

info() {
  printf '\033[1;34m[PID]\033[0m %s\n' "$*"
}

success() {
  printf '\033[1;32m[PID]\033[0m %s\n' "$*"
}

warn() {
  printf '\033[1;33m[PID]\033[0m %s\n' "$*" >&2
}

fail() {
  printf '\033[1;31m[PID]\033[0m %s\n' "$*" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || fail "Required command '$1' is not installed."
}

load_environment() {
  if [[ ! -f "${PROJECT_ROOT}/.env" ]]; then
    fail "Missing .env. Run './scripts/pid.sh setup' first."
  fi

  set -a
  # The local .env is developer-controlled and intentionally excluded from Git.
  # shellcheck disable=SC1091
  source "${PROJECT_ROOT}/.env"
  set +a
}

wait_for_url() {
  local name="$1"
  local url="$2"
  local attempts="${3:-30}"
  local delay="${4:-2}"
  local attempt

  for ((attempt = 1; attempt <= attempts; attempt += 1)); do
    if curl --silent --fail --max-time 2 "${url}" >/dev/null 2>&1; then
      success "${name} is ready."
      return 0
    fi
    sleep "${delay}"
  done

  return 1
}

check_postgres() {
  require_command pg_isready
  pg_isready --dbname="${DATABASE_URL}" --timeout=3 >/dev/null 2>&1
}

compose() {
  docker compose --file "${COMPOSE_FILE}" "$@"
}
