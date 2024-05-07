FROM --platform=$BUILDPLATFORM rust:1.77.2-alpine AS builder

WORKDIR /usr/src/app

RUN apk add --no-cache build-base git musl-dev

COPY . .

ARG TARGETPLATFORM
RUN sh build.sh

FROM alpine:3.18.3

ENV BIND 0.0.0.0:8080

RUN apk add --no-cache tini

COPY --from=builder /tmp/comics /bin/comics

EXPOSE 8080/tcp

ENTRYPOINT ["tini", "--"]
CMD /bin/comics
