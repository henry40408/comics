FROM rust:1.74.1-alpine AS builder

ENV RUSTFLAGS="-C target-feature=-crt-static"

WORKDIR /usr/src/app

RUN apk add --no-cache build-base

COPY . .

RUN cargo build --release

FROM alpine:3.18.3

ENV BIND 0.0.0.0:8080

RUN apk add --no-cache libgcc tini

COPY --from=builder /usr/src/app/target/release/comics /bin/comics

EXPOSE 8080/tcp

ENTRYPOINT ["tini", "--"]
CMD /bin/comics
