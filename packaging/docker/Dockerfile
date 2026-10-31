# netwatch container image.
#
# Built from the musl-static release binary, so nothing here compiles. The
# release workflow prepares `bin/netwatch-amd64` and `bin/netwatch-arm64` from
# the artifacts it just built and hands this file a two-platform buildx.
#
# Not `scratch`, even though the binary is static: netwatch shells out for
# three things on Linux, and each one degrades badly without its tool.
#   ss   (iproute2) — the connection table. Without it the Connections,
#                     Processes and Egress tabs are empty, which looks like a
#                     broken build rather than a missing package.
#   ip   (iproute2) — routes and interface state, so the gateway is known.
#   ping (iputils)  — gateway and internet RTT for the dashboard and the
#                     health checks behind several Diagnose rules.
#   iw              — wireless signal, when the host interface is wifi.
# Traceroute is native on Linux (IP_RECVERR), so no binary is needed for it.
#
# chronyc is deliberately absent: it is only used for NTP clock-offset
# context, pulling in the chrony daemon to get it is not worth ~2 MB, and
# Diagnose reports that input as unmeasured rather than guessing.
FROM alpine:3.22

RUN apk add --no-cache \
        ca-certificates \
        iproute2 \
        iputils \
        iw

ARG TARGETARCH
COPY bin/netwatch-${TARGETARCH} /usr/bin/netwatch

# The TUI needs a sane terminal; without this ratatui gets TERM=dumb and
# draws nothing when someone runs the image with -it.
ENV TERM=xterm-256color

# Capture needs the host's network namespace and CAP_NET_RAW; process
# attribution additionally needs the host PID namespace. See docs/PACKAGING.md.
#   docker run --rm -it --net=host --pid=host \
#     --cap-add=NET_RAW \
#     ghcr.io/matthart1983/netwatch
ENTRYPOINT ["/usr/bin/netwatch"]
