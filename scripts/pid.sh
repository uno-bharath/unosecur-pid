#!/usr/bin/env bash

set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMMAND="${1:-help}"

usage() {
  cat <<'EOF'
UnoSecur PID lifecycle

Usage:
  ./scripts/pid.sh setup      Install, start dependencies, migrate, and seed
  ./scripts/pid.sh start      Start infrastructure, API, and dashboard
  ./scripts/pid.sh all        Run setup and then start the application
  ./scripts/pid.sh status     Show dependency and application health
  ./scripts/pid.sh validate   Run formatting, lint, types, tests, and builds
  ./scripts/pid.sh stop       Stop PID-managed infrastructure
  ./scripts/pid.sh help       Show this help
EOF
}

case "${COMMAND}" in
  setup)
    exec "${SCRIPT_DIR}/setup.sh"
    ;;
  start)
    exec "${SCRIPT_DIR}/start.sh"
    ;;
  all)
    "${SCRIPT_DIR}/setup.sh"
    exec "${SCRIPT_DIR}/start.sh"
    ;;
  status)
    exec "${SCRIPT_DIR}/status.sh"
    ;;
  validate)
    exec "${SCRIPT_DIR}/validate.sh"
    ;;
  stop)
    exec "${SCRIPT_DIR}/stop.sh"
    ;;
  help | --help | -h)
    usage
    ;;
  *)
    usage >&2
    exit 1
    ;;
esac
