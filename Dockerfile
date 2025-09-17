# syntax=docker/dockerfile:1.3-labs
FROM clux/muslrust:1.89.0-stable AS chef
USER root
RUN cargo install cargo-chef --locked
WORKDIR /app

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json

ARG TARGETARCH
RUN <<EOF
set -ex
case "${TARGETARCH}" in
  amd64) target='x86_64-unknown-linux-musl';;
  arm64) target='aarch64-unknown-linux-musl';;
  *) echo "Unsupported architecture: ${TARGETARCH}" && exit 1;;
esac
cargo chef cook --release --target "${target}" --recipe-path recipe.json
EOF

COPY . .
COPY .git .git

RUN <<EOF
set -ex
case "${TARGETARCH}" in
  amd64) target='x86_64-unknown-linux-musl';;
  arm64) target='aarch64-unknown-linux-musl';;
  *) echo "Unsupported architecture: ${TARGETARCH}" && exit 1;;
esac
cargo build --release --target "${target}"
mv /app/target/${target}/release/comics /bin/comics
EOF

FROM alpine:3.22.1 AS runtime
RUN addgroup -S user && adduser -S user -G user
COPY --from=builder /bin/comics /bin/comics
USER user

ENV BIND=0.0.0.0:3000
EXPOSE 3000/tcp
CMD ["/bin/comics"]
