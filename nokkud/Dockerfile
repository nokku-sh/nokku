# Built by GoReleaser, which puts the binary for each platform in the build context. For a local build:
#   CGO_ENABLED=0 go build -o nokkud . && docker build --build-arg BINARY=nokkud -t nokkud:dev .
FROM alpine:3.24.2

ARG TARGETPLATFORM
ARG BINARY=$TARGETPLATFORM/nokkud

# getent is what the daemon resolves accounts with, tini reaps the shells sessions leave behind.
RUN apk add --no-cache ca-certificates musl-utils tini \
 && adduser -D -s /bin/sh dev

COPY $BINARY /usr/bin/nokkud

# The daemon runs as root so sessions can drop to the target user. The state dir holds the enrollment,
# mount it to keep a devbox's identity across restarts, leave it out for a throwaway sandbox.
VOLUME /var/lib/nokkud
EXPOSE 4022

ENTRYPOINT ["/sbin/tini", "--", "nokkud"]
