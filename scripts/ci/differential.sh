#!/usr/bin/env bash
# The full differential suite (ADR-019, issue #170): every scenario in
# tests/differential/scenarios.yaml run against every enforcement point this
# machine has. `cargo test` alone runs the fast subset (the hook decision, and
# any host sandbox whose binary is already on PATH); this script also points the
# suite at the host binaries so the executing host-sandbox layers run too.
#
# A layer whose binary is missing prints a visible "skipped" line and the suite
# still passes on the layers it can run. No step touches the network.
#
#   MOAT_CODEX_BIN   codex binary for the `codex sandbox -P moat` layer
#   MOAT_CLAUDE_BIN  claude binary for the fake-API `claude -p` layer
#   MOAT_FAKE_API    python3 for the fake Anthropic API the claude layer needs
set -euo pipefail
cd "$(dirname "$0")/../.."

# Default to a binary on PATH; override by exporting the variable before running.
: "${MOAT_CODEX_BIN:=$(command -v codex || true)}"
: "${MOAT_CLAUDE_BIN:=$(command -v claude || true)}"
: "${MOAT_FAKE_API:=$(command -v python3 || true)}"
export MOAT_CODEX_BIN MOAT_CLAUDE_BIN MOAT_FAKE_API

echo "▶ differential suite"
echo "  codex:  ${MOAT_CODEX_BIN:-<none; codex layer skipped>}"
echo "  claude: ${MOAT_CLAUDE_BIN:-<none; claude layer skipped>}"

cargo test --locked -p moat-kernel --test e2e differential -- --nocapture
echo "✔ differential suite passed"
