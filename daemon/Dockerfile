# Built by GoReleaser, which puts the binary for each platform in the build context. For a local build:
#   CGO_ENABLED=0 go build -o nokkud ./cmd/nokkud && docker build --build-arg BINARY=nokkud -t nokkud:dev .
FROM debian:13.7-slim

ARG TARGETPLATFORM
ARG BINARY=$TARGETPLATFORM/nokkud

# tini reaps the shells sessions leave behind. getent, which the daemon resolves accounts with, ships in libc-bin.
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ca-certificates tini \
 && rm -rf /var/lib/apt/lists/* \
 && useradd -m -s /bin/bash dev

COPY $BINARY /usr/bin/nokkud

# The daemon runs as root so sessions can drop to the target user. The state dir holds the enrollment,
# mount it to keep a devbox's identity across restarts, leave it out for a throwaway sandbox.
VOLUME /var/lib/nokkud
EXPOSE 4022

ENTRYPOINT ["/usr/bin/tini", "--", "nokkud"]
