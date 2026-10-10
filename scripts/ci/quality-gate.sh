#!/usr/bin/env bash
# The single quality gate. CI and the pre-push hook both run exactly this.
set -euo pipefail
cd "$(dirname "$0")/../.."

run() {
    echo "▶ $*"
    "$@"
}

run cargo fmt --all --check
# fuzz/ is its own workspace (nightly, outside `--all`); rustfmt checks its
# targets on the pinned stable toolchain. CI's fuzz job runs clippy there.
run rustfmt --check --edition 2024 fuzz/fuzz_targets/*.rs
run cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
run cargo doc --locked --workspace --no-deps --document-private-items
run cargo test --locked --workspace --all-features
run cargo run -q --locked -p openmoat -- policy lint crates/openmoat-core/policies/default-v1.yaml
if rustup target list --installed 2>/dev/null | grep -q wasm32-unknown-unknown; then
    run cargo build -q --locked -p openmoat-core --target wasm32-unknown-unknown
else
    echo "▷ wasm32-unknown-unknown target not installed; purity build skipped (CI runs it)"
fi
if command -v shellcheck >/dev/null; then
    echo "▶ shellcheck"
    git ls-files -z '*.sh' .githooks/pre-push | xargs -0 shellcheck
else
    echo "▷ shellcheck not installed; shell script lint skipped (CI runs it)"
fi
if command -v python3 >/dev/null; then
    run python3 scripts/ci/check-links.py
else
    echo "▷ python3 not installed; Markdown link check skipped (CI runs it)"
fi
# tomllib, which reads the manifests, is in the standard library from Python 3.11.
if python3 -c 'import sys; sys.exit(sys.version_info < (3, 11))' 2>/dev/null; then
    run python3 scripts/ci/check-versions.py
else
    echo "▷ python3 ≥ 3.11 needed; release version check skipped (CI runs it)"
fi
if command -v typos >/dev/null; then
    run typos
else
    echo "▷ typos not installed; spell check skipped (CI runs it)"
fi
if command -v cargo-machete >/dev/null; then
    run cargo machete
else
    echo "▷ cargo-machete not installed; unused-dependency check skipped (CI runs it)"
fi
echo "✔ quality gate passed"
