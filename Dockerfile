FROM golang:1.18-alpine as builder

ADD . /koinos-bridge
WORKDIR /koinos-bridge

RUN apk update && \
    apk add \
        gcc \
        musl-dev \
        linux-headers

RUN go get ./... && \
    go build -o koinos_bridge cmd/koinos-bridge-validator/main.go

FROM alpine:latest
COPY --from=builder /koinos-bridge/koinos_bridge /usr/local/bin
# instead of copying the config into the built image, mount it with --mount type=bind,source=/path/to/config.yml,target=/root/.koinos/config.yml
# (SEE README)

CMD [ "/usr/local/bin/koinos_bridge" ]
