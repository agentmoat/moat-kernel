#!/usr/bin/env bash
# The single quality gate. CI and the pre-push hook both run exactly this.
set -euo pipefail
cd "$(dirname "$0")/../.."

run() {
    echo "▶ $*"
    "$@"
}

run cargo fmt --all --check
run cargo clippy --workspace --all-targets --all-features -- -D warnings
run cargo doc --workspace --no-deps --document-private-items
run cargo test --workspace --all-features
run cargo run -q -p moat-kernel -- policy lint policies/default-v1.yaml
echo "✔ quality gate passed"
