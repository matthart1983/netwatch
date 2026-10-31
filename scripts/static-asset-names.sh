#!/bin/sh
# Make netwatch-linux-<arch>-static.tar.gz from netwatch-linux-<arch>.tar.gz, in
# the current directory.
#
# Since 0.31.1 the plain Linux asset is the static binary, and these are the same
# bytes under the name releases used before that. aqua's registry, which mise
# reads, and some Nix and Guix package definitions still ask for it. aqua takes
# the file inside the archive to be named after the archive, so it is renamed too,
# and a copy of the tarball would not do.
set -eu

for arch in x86_64 aarch64; do
    plain="netwatch-linux-${arch}"
    static="${plain}-static"
    dir=$(mktemp -d)
    tar xzf "${plain}.tar.gz" -C "${dir}"
    mv "${dir}/${plain}" "${dir}/${static}"
    tar czf "${static}.tar.gz" -C "${dir}" "${static}"
    rm -rf "${dir}"
done
