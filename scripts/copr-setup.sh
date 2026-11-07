#!/usr/bin/env bash
# One-off COPR project setup, driven by the API instead of the web UI.
#
# Needs an API token: log in at https://copr.fedorainfracloud.org, open
# https://copr.fedorainfracloud.org/api/ and save the config block it shows to
# ~/.config/copr. That page is the only step that needs a browser.
#
#   scripts/copr-setup.sh
#
# Creates the project, registers packaging/rpm/netwatch.spec as an SCM package
# and kicks off the first build. Safe to re-run: it reports what already exists.
set -euo pipefail

CFG="${COPR_CONFIG:-$HOME/.config/copr}"
PROJECT="${COPR_PROJECT:-netwatch}"
REPO_URL="https://github.com/matthart1983/netwatch"
SPEC="packaging/rpm/netwatch.spec"
# A new Fedora needs its chroots added here and in the project's settings
# (re-running this script does not change an existing project's chroots).
# install-check.yml fails on the newest Fedora until it has them.
CHROOTS=(fedora-43-x86_64 fedora-43-aarch64 fedora-44-x86_64 fedora-44-aarch64
    fedora-45-x86_64 fedora-45-aarch64 fedora-rawhide-x86_64)

[ -r "${CFG}" ] || { echo "No COPR config at ${CFG} — see the header of this script." >&2; exit 1; }

get() { sed -n "s/^$1 *= *//p" "${CFG}" | tr -d '[:space:]'; }
LOGIN=$(get login); TOKEN=$(get token); USERNAME=$(get username)
URL=$(get copr_url); URL="${URL:-https://copr.fedorainfracloud.org}"
[ -n "${LOGIN}" ] && [ -n "${TOKEN}" ] && [ -n "${USERNAME}" ] || {
    echo "${CFG} is missing login, token or username" >&2; exit 1; }

api() { # api METHOD PATH [curl args...]
    local method="$1" path="$2"; shift 2
    curl -sS -u "${LOGIN}:${TOKEN}" -X "${method}" "${URL}/api_3/${path}" "$@"
}

echo "==> Creating project ${USERNAME}/${PROJECT}"
chroot_args=()
for c in "${CHROOTS[@]}"; do chroot_args+=(-F "chroots=${c}"); done
api POST "project/add/${USERNAME}" \
    -F "name=${PROJECT}" \
    -F "description=Real-time network diagnostics in your terminal" \
    -F "instructions=sudo dnf copr enable ${USERNAME}/${PROJECT} && sudo dnf install netwatch" \
    -F "unlisted_on_hp=false" \
    "${chroot_args[@]}" | head -c 400; echo

echo "==> Registering the SCM package"
api POST "package/add/${USERNAME}/${PROJECT}/netwatch/scm" \
    -F "package_name=netwatch" \
    -F "clone_url=${REPO_URL}" \
    -F "committish=main" \
    -F "spec=${SPEC}" \
    -F "scm_type=git" \
    -F "source_build_method=rpkg" \
    -F "webhook_rebuild=true" | head -c 400; echo

echo "==> Starting the first build"
api POST "package/build" \
    -F "ownername=${USERNAME}" \
    -F "projectname=${PROJECT}" \
    -F "package_name=netwatch" | head -c 400; echo

echo
echo "Watch it at ${URL}/coprs/${USERNAME}/${PROJECT}/builds/"
