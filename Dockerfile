FROM golang:1.20.5-alpine3.18 AS build

ENV CGO_ENABLED=0

RUN apk add --no-cache git

ADD . /go/src/app

WORKDIR /go/src/app

RUN go build \
  -o comics \
  -ldflags="-s -w -X 'comics.app/version.Version=`git describe --tags --abbrev=0`' -X 'comics.app/version.Commit=`git rev-parse --short HEAD`' -X 'comics.app/version.BuildDate=`date +%FT%T%z`'" \
  main.go

FROM alpine:3.18.2

LABEL org.opencontainers.image.title=Comics
LABEL org.opencontainers.image.description="Simple file server for comic books"
LABEL org.opencontainers.image.vendor="henry40408"
LABEL org.opencontainers.image.licenses=MIT
LABEL org.opencontainers.image.url=https://github.com/henry40408/comics
LABEL org.opencontainers.image.source=https://github.com/henry40408/comics
LABEL org.opencontainers.image.documentation=https://github.com/henry40408/comics

EXPOSE 8080
RUN apk --no-cache add ca-certificates tzdata
COPY --from=build /go/src/app/comics /usr/bin/comics
USER nobody
CMD ["/usr/bin/comics"]
