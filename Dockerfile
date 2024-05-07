FROM rust:1.77.2-alpine AS builder

WORKDIR /usr/src/app
RUN apk add --no-cache build-base=0.5-r3 git=2.43.0-r0 musl-dev=1.2.4_git20230717-r4
COPY . .
COPY .git .git

ARG TARGETPLATFORM
RUN sh build.sh

FROM alpine:3.19.1

ENV BIND 0.0.0.0:8080
RUN apk add --no-cache tini=0.19.0-r2
COPY --from=builder /tmp/comics /bin/comics
EXPOSE 8080/tcp

ENTRYPOINT ["tini", "--"]
CMD ["/bin/comics"]
