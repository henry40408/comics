#!/usr/bin/env sh

set -euo pipefail

if [[ "$TARGETPLATFORM" = "linux/amd64" ]]; then
	rustup target add x86_64-unknown-linux-musl
	cargo build --release --target x86_64-unknown-linux-musl
	cp target/x86_64-unknown-linux-musl/release/comics /tmp/comics
elif [[ "$TARGETPLATFORM" = "linux/arm64" ]]; then
	rustup target add aarch64-unknown-linux-musl
	cargo build --release --target aarch64-unknown-linux-musl
	cp target/aarch64-unknown-linux-musl/release/comics /tmp/comics
else
	echo "target platform $TARGETPLATFORM not supported"
	exit 1
fi
