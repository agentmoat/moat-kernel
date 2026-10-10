#!/usr/bin/env bash
# The single quality gate. CI and the pre-push hook both run exactly this.
set -euo pipefail
cd "$(dirname "$0")/../.."

run() {
    echo "▶ $*"
    "$@"
}

run cargo fmt --all --check
run cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
run cargo doc --locked --workspace --no-deps --document-private-items
run cargo test --locked --workspace --all-features
run cargo run -q --locked -p openmoat -- policy lint crates/openmoat-core/policies/default-v1.yaml
if rustup target list --installed 2>/dev/null | grep -q wasm32-unknown-unknown; then
    run cargo build -q --locked -p openmoat-core --target wasm32-unknown-unknown
else
    echo "▷ wasm32-unknown-unknown target not installed; purity build skipped (CI runs it)"
fi
if command -v typos >/dev/null; then
    run typos
else
    echo "▷ typos not installed; spell check skipped (CI runs it)"
fi
echo "✔ quality gate passed"
