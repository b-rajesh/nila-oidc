#!/usr/bin/env bash
set -euo pipefail
rustup run 1.86.0 cargo check --workspace --all-features
rustup run 1.86.0 cargo clippy --workspace --all-targets --all-features -- -D warnings
rustup run 1.86.0 cargo test --workspace --all-features
echo "✅ 1.86.0 / 2024-edition ready"