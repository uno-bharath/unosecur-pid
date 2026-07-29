#!/usr/bin/env bash

set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

require_command docker

info "Stopping PID-managed Redis and Neo4j containers."
compose down
success "Infrastructure stopped. PostgreSQL and Ollama were left running because PID does not manage them."
