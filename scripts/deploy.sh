#!/usr/bin/env bash

set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
COMPOSE_FILE="${PROJECT_ROOT}/infrastructure/docker/compose.deploy.yml"
ENV_FILE="${PROJECT_ROOT}/.env.deploy"
ACTION="${1:-up}"

info() {
  printf '\033[1;34m[PID]\033[0m %s\n' "$*"
}

success() {
  printf '\033[1;32m[PID]\033[0m %s\n' "$*"
}

error() {
  printf '\033[1;31m[PID]\033[0m %s\n' "$*" >&2
}

detect_os() {
  case "$(uname -s 2>/dev/null || true)" in
    Darwin)
      PID_OS="macos"
      ;;
    Linux)
      if grep -qi microsoft /proc/version 2>/dev/null; then
        PID_OS="wsl"
      else
        PID_OS="linux"
      fi
      ;;
    *)
      PID_OS="unsupported"
      ;;
  esac
}

install_docker_macos() {
  if ! command -v brew >/dev/null 2>&1; then
    error "Docker is missing and Homebrew is not installed."
    error "Install Docker Desktop from https://www.docker.com/products/docker-desktop/ and rerun this script."
    exit 1
  fi

  info "Installing Docker Desktop with Homebrew..."
  brew install --cask docker
}

run_as_root() {
  if [ "$(id -u)" -eq 0 ]; then
    "$@"
  elif command -v sudo >/dev/null 2>&1; then
    sudo "$@"
  else
    error "Administrator permission is required to install Docker."
    exit 1
  fi
}

install_docker_linux() {
  info "Installing Docker Engine and Compose..."

  if command -v apt-get >/dev/null 2>&1; then
    run_as_root apt-get update
    run_as_root apt-get install -y docker.io docker-compose-v2
  elif command -v dnf >/dev/null 2>&1; then
    run_as_root dnf install -y docker docker-compose-plugin
  elif command -v yum >/dev/null 2>&1; then
    run_as_root yum install -y docker docker-compose-plugin
  elif command -v pacman >/dev/null 2>&1; then
    run_as_root pacman -Sy --noconfirm docker docker-compose
  elif command -v zypper >/dev/null 2>&1; then
    run_as_root zypper --non-interactive install docker docker-compose
  elif command -v apk >/dev/null 2>&1; then
    run_as_root apk add docker docker-cli-compose
  else
    error "No supported package manager was detected."
    error "Install Docker Engine with Compose, then rerun this script."
    exit 1
  fi
}

ensure_docker_installed() {
  if command -v docker >/dev/null 2>&1; then
    return
  fi

  case "${PID_OS}" in
    macos)
      install_docker_macos
      ;;
    linux)
      install_docker_linux
      ;;
    wsl)
      error "Docker is not available inside WSL."
      error "Enable Docker Desktop WSL integration, reopen the terminal, and rerun this script."
      exit 1
      ;;
    *)
      error "Unsupported operating system. Use macOS, Linux, or Windows with WSL2."
      exit 1
      ;;
  esac
}

wait_for_docker() {
  if docker info >/dev/null 2>&1; then
    return
  fi

  case "${PID_OS}" in
    macos)
      info "Starting Docker Desktop..."
      open -a Docker
      ;;
    linux)
      if command -v systemctl >/dev/null 2>&1; then
        run_as_root systemctl start docker
      elif command -v service >/dev/null 2>&1; then
        run_as_root service docker start
      fi
      ;;
  esac

  info "Waiting for Docker to become ready..."
  attempt=0
  until docker info >/dev/null 2>&1; do
    attempt=$((attempt + 1))
    if [ "${attempt}" -ge 60 ]; then
      error "Docker did not become ready within two minutes."
      exit 1
    fi
    sleep 2
  done
}

ensure_compose() {
  if ! docker compose version >/dev/null 2>&1; then
    error "Docker Compose v2 is required but was not detected."
    exit 1
  fi
}

random_secret() {
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex 24
  else
    date_value="$(date +%s 2>/dev/null || printf 'pid')"
    printf '%s' "${date_value}-${RANDOM}-${RANDOM}" | sha256sum | cut -d ' ' -f 1
  fi
}

write_environment() {
  if [ -f "${ENV_FILE}" ]; then
    info "Using existing .env.deploy configuration."
    return
  fi

  postgres_secret="$(random_secret)"
  redis_secret="$(random_secret)"
  neo4j_secret="$(random_secret)"
  public_host="${PID_PUBLIC_HOST:-localhost}"
  web_port="${PID_WEB_PORT:-3000}"
  api_port="${PID_API_PORT:-4000}"

  umask 077
  {
    printf 'POSTGRES_DB=unosecur_pid\n'
    printf 'POSTGRES_USER=unosecur_pid\n'
    printf 'POSTGRES_PASSWORD=%s\n' "${postgres_secret}"
    printf 'POSTGRES_PORT=%s\n\n' "${PID_POSTGRES_PORT:-5432}"
    printf 'REDIS_PASSWORD=%s\n' "${redis_secret}"
    printf 'REDIS_PORT=%s\n\n' "${PID_REDIS_PORT:-6379}"
    printf 'NEO4J_USER=neo4j\n'
    printf 'NEO4J_PASSWORD=%s\n' "${neo4j_secret}"
    printf 'NEO4J_HTTP_PORT=%s\n' "${PID_NEO4J_HTTP_PORT:-7474}"
    printf 'NEO4J_BOLT_PORT=%s\n\n' "${PID_NEO4J_BOLT_PORT:-7687}"
    printf 'API_PORT=%s\n' "${api_port}"
    printf 'WEB_PORT=%s\n' "${web_port}"
    printf 'PUBLIC_API_URL=http://%s:%s/api\n' "${public_host}" "${api_port}"
    printf 'WEB_ORIGIN=http://%s:%s\n\n' "${public_host}" "${web_port}"
    printf 'OLLAMA_BASE_URL=http://host.docker.internal:11434\n'
    printf 'OLLAMA_MODEL=%s\n' "${PID_OLLAMA_MODEL:-qwen3:4b}"
  } >"${ENV_FILE}"

  success "Created private deployment configuration at .env.deploy."
}

compose() {
  if [ -f "${PROJECT_ROOT}/.env" ]; then
    docker compose --env-file "${PROJECT_ROOT}/.env" --env-file "${ENV_FILE}" -f "${COMPOSE_FILE}" "$@"
  else
    docker compose --env-file "${ENV_FILE}" -f "${COMPOSE_FILE}" "$@"
  fi
}

show_urls() {
  # shellcheck disable=SC1090
  set -a
  source "${ENV_FILE}"
  set +a

  success "UnoSecur PID is running."
  printf '\n'
  printf '  Dashboard:      http://localhost:%s\n' "${WEB_PORT:-3000}"
  printf '  API:            http://localhost:%s/api\n' "${API_PORT:-4000}"
  printf '  API health:     http://localhost:%s/api/health\n' "${API_PORT:-4000}"
  printf '  Swagger:        http://localhost:%s/docs\n' "${API_PORT:-4000}"
  printf '  Neo4j Browser:  http://localhost:%s\n' "${NEO4J_HTTP_PORT:-7474}"
  printf '\n'
  printf 'Use ./scripts/deploy.sh logs to follow logs and ./scripts/deploy.sh down to stop PID.\n'
}

deploy() {
  detect_os
  info "Detected operating system: ${PID_OS}."
  ensure_docker_installed
  wait_for_docker
  ensure_compose
  write_environment

  info "Building images and starting the complete PID stack..."
  compose up --detach --build --wait
  show_urls
}

case "${ACTION}" in
  up | deploy | start)
    deploy
    ;;
  down | stop)
    [ -f "${ENV_FILE}" ] || {
      error ".env.deploy does not exist; no managed deployment was found."
      exit 1
    }
    compose down
    success "UnoSecur PID stopped. Persistent data was retained."
    ;;
  reset)
    [ -f "${ENV_FILE}" ] || {
      error ".env.deploy does not exist; no managed deployment was found."
      exit 1
    }
    compose down --volumes
    success "UnoSecur PID stopped and its managed data volumes were removed."
    ;;
  status)
    [ -f "${ENV_FILE}" ] || {
      error ".env.deploy does not exist; no managed deployment was found."
      exit 1
    }
    compose ps
    ;;
  logs)
    [ -f "${ENV_FILE}" ] || {
      error ".env.deploy does not exist; no managed deployment was found."
      exit 1
    }
    compose logs --follow --tail=200
    ;;
  *)
    cat <<'EOF'
Usage: ./scripts/deploy.sh [up|down|reset|status|logs]

  up       Detect the OS, install/verify Docker, build, migrate, seed, and run PID
  down     Stop the application while retaining its data
  reset    Stop the application and remove its managed data
  status   Show service health
  logs     Follow application and infrastructure logs

Optional environment overrides:
  PID_PUBLIC_HOST       Browser-visible hostname or IP (default: localhost)
  PID_WEB_PORT          Dashboard port (default: 3000)
  PID_API_PORT          API port (default: 4000)
  PID_POSTGRES_PORT     PostgreSQL port (default: 5432)
  PID_REDIS_PORT        Redis port (default: 6379)
  PID_NEO4J_HTTP_PORT   Neo4j browser port (default: 7474)
  PID_NEO4J_BOLT_PORT   Neo4j Bolt port (default: 7687)
  PID_OLLAMA_MODEL      Optional host Ollama model (default: qwen3:4b)
EOF
    exit 1
    ;;
esac
