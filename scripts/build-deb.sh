#!/usr/bin/env bash
# Build the fork's .deb: a static musl x86_64 binary with libpcap linked in, as
# the upstream release does, with the service set up for the connection log.
# The package itself depends on nothing; install it with
# `sudo apt install ./target/netwatch_<version>_amd64.deb`.
#
#   scripts/build-deb.sh [DEB_VERSION]      # default: <crate version>+flowlog1
#
# Build dependencies, all from apt:
#   sudo apt install musl-tools flex bison make curl file binutils dpkg-dev linux-libc-dev
# and Rust at least the crate's rust-version, with the musl target. Ubuntu's
# apt Rust is older than that, so it comes from rustup:
#   rustup target add x86_64-unknown-linux-musl
# Nothing here runs as root.
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
RUST_VERSION="$(sed -n 's/^rust-version = "\(.*\)"/\1/p' Cargo.toml | head -1)"
DEB_VERSION="${1:-${CRATE_VERSION}+flowlog1}"
MAINTAINER="Iurii Kolesov <iurii.kolesov@alberblanc.com>"
WORK="$ROOT/target/deb-build"

# tool → the apt package that has it
missing=()
for pair in musl-gcc:musl-tools make:make flex:flex bison:bison curl:curl \
    file:file strip:binutils dpkg-deb:dpkg-deb gcc:gcc; do
    command -v "${pair%%:*}" >/dev/null || missing+=("${pair#*:}")
done
[ -d /usr/include/linux ] || missing+=(linux-libc-dev)
if [ ${#missing[@]} -gt 0 ]; then
    echo "missing build dependencies: sudo apt install ${missing[*]}" >&2
    exit 1
fi
have_rust="$(rustc --version 2>/dev/null | awk '{print $2}')"
if [ -z "$have_rust" ] || [ "$(printf '%s\n%s\n' "$RUST_VERSION" "$have_rust" | sort -V | head -1)" != "$RUST_VERSION" ]; then
    echo "need Rust >= $RUST_VERSION (have ${have_rust:-none}); apt's is older, use rustup" >&2
    exit 1
fi
rustup target list --installed 2>/dev/null | grep -qx "$TARGET" \
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
# Laid out by hand and built with dpkg-deb. The file list is the one
# [package.metadata.deb] in Cargo.toml gives cargo-deb, which upstream's
# release uses; keep the two in step.
STAGE="$WORK/stage"
rm -rf "$STAGE"
install -Dm755 "$bin" "$STAGE/usr/bin/netwatch"
strip --strip-unneeded "$STAGE/usr/bin/netwatch"
install -Dm644 completions/netwatch.bash "$STAGE/usr/share/bash-completion/completions/netwatch"
install -Dm644 completions/_netwatch "$STAGE/usr/share/zsh/site-functions/_netwatch"
install -Dm644 completions/netwatch.fish "$STAGE/usr/share/fish/vendor_completions.d/netwatch.fish"
install -Dm644 docs/netwatch.1 "$STAGE/usr/share/man/man1/netwatch.1"
gzip -9n "$STAGE/usr/share/man/man1/netwatch.1"
install -Dm644 packaging/systemd/netwatch.service "$STAGE/usr/lib/systemd/system/netwatch.service"
install -Dm644 README.md "$STAGE/usr/share/doc/netwatch/README.md"
install -Dm644 CHANGELOG.md "$STAGE/usr/share/doc/netwatch/CHANGELOG.md"
{
    echo "Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/"
    echo "Upstream-Name: netwatch"
    echo "Source: https://github.com/yuri-research-ai/netwatch"
    echo
    echo "Files: *"
    echo "Copyright: 2026, Matt Hartley"
    echo "License: MIT"
    sed 's/^$/./; s/^/ /' LICENSE
} >"$STAGE/usr/share/doc/netwatch/copyright"
chmod 644 "$STAGE/usr/share/doc/netwatch/copyright"

mkdir -p "$STAGE/DEBIAN"
for script in postinst prerm postrm; do
    install -m755 "packaging/debian/$script" "$STAGE/DEBIAN/$script"
done
cat >"$STAGE/DEBIAN/control" <<CONTROL
Package: netwatch
Version: $DEB_VERSION
Architecture: amd64
Maintainer: $MAINTAINER
Installed-Size: $(du -sk --exclude=DEBIAN "$STAGE" | cut -f1)
Section: net
Priority: optional
Homepage: https://github.com/yuri-research-ai/netwatch
Description: Network diagnostics in your terminal, with a connection log
 netwatch with a connection log: the daemon, run as a systemd service under
 its own unprivileged user, writes one NDJSON line when a connection opens and
 one when it closes (process, pid, destination, SNI/host, duration) to
 /var/log/netwatch. Also the terminal UI: live per-connection throughput with
 application-protocol decoding, process attribution and a diagnostic engine.
 .
 The binary is static (musl, libpcap linked in), so the package has no
 dependencies.
CONTROL
(cd "$STAGE" && find . -path ./DEBIAN -prune -o -type f -printf '%P\0' \
    | sort -z | xargs -0 md5sum >DEBIAN/md5sums)

deb="target/netwatch_${DEB_VERSION}_amd64.deb"
dpkg-deb --root-owner-group -Zxz --build "$STAGE" "$deb" >/dev/null
dpkg-deb --info "$deb" | sed -n '/Package:/,$p'
dpkg-deb --contents "$deb"
echo
echo "built $deb"
echo "install: sudo apt install ./$deb"
