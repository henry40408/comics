FROM rust:1.89.0-alpine AS builder

WORKDIR /usr/src/app
RUN apk add --no-cache build-base git
COPY . .
COPY .git .git

RUN cargo build --release

FROM alpine:3.19.1

ENV BIND=0.0.0.0:8080
RUN apk add --no-cache tini=0.19.0-r2
COPY --from=builder /usr/src/app/target/release/comics /bin/comics
EXPOSE 8080/tcp

ENTRYPOINT ["tini", "--"]
CMD ["/bin/comics"]
