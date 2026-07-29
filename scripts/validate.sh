#!/usr/bin/env bash

set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

require_command pnpm

info "Running formatting, lint, type, test, and production-build checks."
cd "${PROJECT_ROOT}"
pnpm format:check
pnpm lint
pnpm typecheck
pnpm test
pnpm build
success "All UnoSecur PID validation checks passed."
