ARG TARGET_OS
ARG TARGET_ARCH
FROM golang:1.23.6 AS builder
ENV GO111MODULE=on \
  CGO_ENABLED=0 \
  GOOS=${TARGET_OS} \
  GOARCH=${TARGET_ARCH} \
  CONTAINER_BUILD=1


WORKDIR /go/src/github.com/framjet/go-cloudflare-access-external-evaluation/

COPY . .

RUN PATH="/tmp/go/bin:$PATH" make framjet-cfa-ex-eval

# use a distroless base image with glibc
FROM gcr.io/distroless/base-debian11:debug-nonroot

LABEL org.opencontainers.image.source="https://github.com/framjet/go-cloudflare-access-external-evaluation"

# copy our compiled binary
COPY --from=builder --chown=nonroot /go/src/github.com/framjet/go-cloudflare-access-external-evaluation/framjet-cfa-ex-eval /usr/local/bin/
COPY --from=builder --chown=nonroot /go/src/github.com/framjet/go-cloudflare-access-external-evaluation/docker-entrypoint.sh /usr/local/bin/

# run as non-privileged user
USER nonroot

# command / entrypoint of container
ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["framjet-cfa-ex-eval"]