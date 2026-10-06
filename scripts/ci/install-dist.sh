#!/usr/bin/env bash
# Installs the dist (cargo-dist) release pinned below into ~/.cargo/bin. The hashes
# are those of the upstream release assets, whose build provenance was checked with
# `gh attestation verify --repo axodotdev/cargo-dist`; bump them together with
# `cargo-dist-version` in dist-workspace.toml.
set -euo pipefail

version=0.32.0
case "$(uname -s)-$(uname -m)" in
    Darwin-arm64) target=aarch64-apple-darwin sha=aa343b2ff78ec2981f17a65140250c5ad6062c74072163f68c5c2686d94763a7 ;;
    Darwin-x86_64) target=x86_64-apple-darwin sha=6243464a8389e006b9256ee548bc795638f1a17113c1b6669c0e05ce89fd05c5 ;;
    Linux-x86_64) target=x86_64-unknown-linux-gnu sha=eb52f9fae0d0506774e9f1801c1168f87fa2c87a45e2d64d3ae7c89401929946 ;;
    Linux-aarch64) target=aarch64-unknown-linux-gnu sha=d29bcffeb3f8b0c517b4ce0dd2470926ed5cb0bb29d78c6bdd5f88d76ee14a6a ;;
    MINGW*-x86_64 | MSYS*-x86_64) target=x86_64-pc-windows-msvc sha=26e845cabff12a92911ce960af73a86c8f9b2b2d9072b01dfe5b662acf044fa3 ;;
    *)
        echo "no pinned dist for $(uname -s)-$(uname -m)" >&2
        exit 1
        ;;
esac

case "$target" in
    *windows*) archive="cargo-dist-$target.zip" ;;
    *) archive="cargo-dist-$target.tar.xz" ;;
esac

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cd "$work"
curl --proto '=https' --tlsv1.2 -fsSLo "$archive" \
    "https://github.com/axodotdev/cargo-dist/releases/download/v$version/$archive"
if command -v sha256sum >/dev/null; then
    echo "$sha  $archive" | sha256sum -c -
else
    echo "$sha  $archive" | shasum -a 256 -c -
fi

bin="$HOME/.cargo/bin"
mkdir -p "$bin"
case "$archive" in
    *.zip)
        7z e -y "$archive" dist.exe >/dev/null
        mv dist.exe "$bin/"
        ;;
    *)
        tar xJf "$archive" --strip-components=1 "cargo-dist-$target/dist"
        mv dist "$bin/"
        ;;
esac
"$bin/dist" --version
