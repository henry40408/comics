# syntax=docker/dockerfile:1

# ---- build: cross-compile a static musl binary with cargo-zigbuild ----------
# Runs on the native build platform; zig cross-compiles to the target's musl
# triple, so no qemu. mimalloc is the only C dependency (zig cc builds it).
# No Rust version tag: rust-toolchain.toml is the single source of truth. Keep
# the `bookworm` suffix — a bare tag resolves to trixie, a silent Debian bump.
FROM --platform=$BUILDPLATFORM rust:bookworm AS build

# curl + xz fetch zig.
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl xz-utils \
    && rm -rf /var/lib/apt/lists/*

# Zig 0.14.1 avoids the libc++-19 bindgen requirement that 0.15+ introduces.
ARG ZIG_VERSION=0.14.1
# At least 0.23.0: earlier releases pass rustc's `-Wl,--fix-cortex-a53-843419`
# (aarch64 musl) through to zig cc, which rejects it.
ARG ZIGBUILD_VERSION=0.23.4
RUN cargo install cargo-zigbuild --version "${ZIGBUILD_VERSION}" --locked
RUN set -eux; \
    case "$(uname -m)" in \
      x86_64) zarch=x86_64 ;; \
      aarch64) zarch=aarch64 ;; \
      *) echo "unsupported build arch $(uname -m)" >&2; exit 1 ;; \
    esac; \
    curl -fsSL "https://ziglang.org/download/${ZIG_VERSION}/zig-${zarch}-linux-${ZIG_VERSION}.tar.xz" \
      | tar -xJ -C /opt; \
    ln -s "/opt/zig-${zarch}-linux-${ZIG_VERSION}/zig" /usr/local/bin/zig

WORKDIR /app

# Install the pinned toolchain in a layer keyed on rust-toolchain.toml alone, so
# source edits do not re-download the compiler.
COPY rust-toolchain.toml .
RUN cargo --version

COPY . .

# Map Docker's TARGETARCH onto the Rust musl triple and build.
ARG TARGETARCH
ARG GIT_VERSION=dev
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/app/target,sharing=locked \
    set -eux; \
    case "$TARGETARCH" in \
      amd64) target=x86_64-unknown-linux-musl ;; \
      arm64) target=aarch64-unknown-linux-musl ;; \
      *) echo "unsupported target arch $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    rustup target add "$target"; \
    GIT_VERSION="${GIT_VERSION}" cargo zigbuild --release --target "$target"; \
    install -Dm755 "target/${target}/release/comics" /out/comics

# ---- runtime: minimal static image (CA certs + tzdata, no shell) ------------
# Not :nonroot — running as root keeps bind-mounted data/cache dirs writable
# without a permissions change.
FROM gcr.io/distroless/static-debian12
COPY --from=build /out/comics /comics

ENV COMICS_BIND=0.0.0.0:8080

EXPOSE 8080

ENTRYPOINT ["/comics"]
