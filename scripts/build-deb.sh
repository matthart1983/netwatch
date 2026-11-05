#!/usr/bin/env bash
# Build the fork's .deb: a static musl x86_64 binary with libpcap linked in, as
# the upstream release does, packaged by cargo-deb's `flowlog` variant with the
# service set up for the connection log.
#
#   scripts/build-deb.sh [DEB_VERSION]      # default: <crate version>+flowlog1
#
# Needs, all without root:
#   - the rustup toolchain rust-toolchain/override picks, with the
#     x86_64-unknown-linux-musl target (`rustup target add x86_64-unknown-linux-musl`)
#   - musl-gcc (Debian/Ubuntu: musl-tools), make, flex, bison, curl
#   - cargo-deb on PATH, or CARGO_DEB=/path/to/cargo-deb
#
# The libpcap tarball is checked against the SHA-256 pinned below, taken from
# the release whose tcpdump.org signature (key E089DEF1D9C15D0D) verified.
# Everything is built under target/deb-build; the package lands in target/.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

TARGET=x86_64-unknown-linux-musl
LIBPCAP_VERSION=1.10.5
LIBPCAP_SHA256=37ced90a19a302a7f32e458224a00c365c117905c2cd35ac544b6880a81488f0
CRATE_VERSION="$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)"
DEB_VERSION="${1:-${CRATE_VERSION}+flowlog1}"
CARGO_DEB="${CARGO_DEB:-cargo-deb}"
WORK="$ROOT/target/deb-build"

for tool in musl-gcc make flex bison curl "$CARGO_DEB"; do
    command -v "$tool" >/dev/null || { echo "missing: $tool" >&2; exit 1; }
done
rustup target list --installed | grep -qx "$TARGET" \
    || { echo "missing rust target: rustup target add $TARGET" >&2; exit 1; }

# ── static libpcap ──────────────────────────────────────────────────────────
PREFIX="$WORK/pcap-$LIBPCAP_VERSION"
if [ ! -f "$PREFIX/lib/libpcap.a" ]; then
    mkdir -p "$WORK/src"
    tarball="$WORK/src/libpcap-$LIBPCAP_VERSION.tar.gz"
    [ -f "$tarball" ] || curl --proto '=https' -sSfL -o "$tarball" \
        "https://www.tcpdump.org/release/libpcap-$LIBPCAP_VERSION.tar.gz"
    echo "$LIBPCAP_SHA256  $tarball" | sha256sum -c --quiet - \
        || { echo "libpcap tarball checksum mismatch" >&2; rm -f "$tarball"; exit 1; }
    rm -rf "$WORK/src/libpcap-$LIBPCAP_VERSION"
    tar xzf "$tarball" -C "$WORK/src"
    # musl-gcc searches musl's headers only. libpcap needs the kernel's
    # (linux-libc-dev), so expose those three directories and nothing of glibc.
    kheaders="$WORK/kernel-headers"
    mkdir -p "$kheaders"
    arch_include="/usr/include/$(gcc -dumpmachine 2>/dev/null || echo x86_64-linux-gnu)"
    for d in /usr/include/linux "$arch_include/asm" /usr/include/asm-generic; do
        [ -d "$d" ] || { echo "missing kernel headers: $d (install linux-libc-dev)" >&2; exit 1; }
        ln -sfn "$d" "$kheaders/$(basename "$d")"
    done
    (
        cd "$WORK/src/libpcap-$LIBPCAP_VERSION"
        # The flags the upstream release uses: no optional capture backends,
        # so the static library pulls in nothing else.
        CC=musl-gcc CFLAGS="-O2 -I$kheaders" ./configure \
            --host=x86_64-linux-musl \
            --prefix="$PREFIX" \
            --with-pcap=linux \
            --disable-shared \
            --disable-dbus \
            --disable-bluetooth \
            --disable-rdma \
            --disable-usb \
            --without-libnl >"$WORK/libpcap-configure.log"
        make -j"$(nproc)" >"$WORK/libpcap-make.log"
        make install >>"$WORK/libpcap-make.log"
    )
fi

# ── netwatch ────────────────────────────────────────────────────────────────
export LIBPCAP_LIBDIR="$PREFIX/lib"
export LIBPCAP_VER="$LIBPCAP_VERSION"
export PKG_CONFIG_PATH="$PREFIX/lib/pkgconfig"
export PKG_CONFIG_ALL_STATIC=1
export PKG_CONFIG_ALLOW_CROSS=1
# C dependencies (mimalloc) are built for musl too.
export CC_x86_64_unknown_linux_musl=musl-gcc
cargo build --release --locked --target "$TARGET"

bin="target/$TARGET/release/netwatch"
if file "$bin" | grep -q 'dynamically linked'; then
    echo "$bin is dynamically linked; expected a static binary" >&2
    exit 1
fi
"$bin" --version

# ── package ─────────────────────────────────────────────────────────────────
"$CARGO_DEB" --no-build --target "$TARGET" --variant flowlog \
    --deb-version "$DEB_VERSION" --output target/
deb="target/netwatch_${DEB_VERSION}_amd64.deb"
dpkg-deb --info "$deb" | sed -n '/Package:/,$p'
dpkg-deb --contents "$deb"
echo
echo "built $deb"
echo "install: sudo apt install ./$deb"
