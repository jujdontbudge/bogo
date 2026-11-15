#!/bin/sh
# Cross-builds the shim and the bypass suite for the agent image, then builds
# the sandbox images. Needs `cargo zigbuild` (brew install zig; cargo install
# cargo-zigbuild) and the aarch64-unknown-linux-musl (or x86_64) Rust target.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
case "$(docker info --format '{{.Architecture}}')" in
	aarch64|arm64) target=aarch64-unknown-linux-musl ;;
	x86_64|amd64) target=x86_64-unknown-linux-musl ;;
	*) echo "unsupported Docker architecture" >&2; exit 1 ;;
esac
cd "$here/.."
CARGO_PROFILE_RELEASE_STRIP=true cargo zigbuild --release --target "$target" -p bogo-shim -p bogo-bypass
mkdir -p "$here/agent/bin"
cp "target/$target/release/bogo-shim" "target/$target/release/bogo-bypass" "$here/agent/bin/"
cd "$here"
docker compose build
