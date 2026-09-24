#!/bin/sh
# Build every plugin, plus the binaries named by BLOCKY_PKG_DIR, into a per-ABI pkg
# repository at repo/<ABI>/. With DEV_REPO_URL set, build a second repository at
# repo-dev/<ABI>/ holding the same packages layered onto what that channel already
# has. Invoked by the build workflow.
set -e

SELF=$(cd "$(dirname "$0")/.." && pwd)
ABI=$(pkg config abi)
STAGE="${SELF}/stage"
OUT="${SELF}/repo/${ABI}"
rm -rf "${STAGE}" "${OUT}"; mkdir -p "${STAGE}" "${OUT}"

# each <category>/<name>/ carrying a plugin Makefile
for mk in "${SELF}"/*/*/Makefile; do
    grep -q 'Mk/plugins.mk' "${mk}" 2>/dev/null || continue
    pdir=$(dirname "${mk}")
    make -C "${pdir}" package
    find "${pdir}/work" -name '*.pkg' -exec cp {} "${STAGE}/" \;
done

# blocky binary, built separately by build-blocky-port.sh
[ -n "${BLOCKY_PKG_DIR}" ] && cp "${BLOCKY_PKG_DIR}"/blocky-*.pkg "${STAGE}/" 2>/dev/null || true

cp "${STAGE}"/*.pkg "${OUT}/" 2>/dev/null || true
pkg repo "${OUT}" ${REPO_SIGNING_KEY:+"${REPO_SIGNING_KEY}"}

# site root: pkg client config (landing/changelog built at deploy by build-site.sh)
cp "${SELF}/tools/greelan.conf" "${SELF}/repo/greelan.conf"

# Testing channel: the same packages layered onto what the channel already holds, so a
# package another branch published there survives this build. Newest version of each
# name wins, whichever side it came from. Kept apart from the production repository
# above, which must never carry a package that only exists on a branch.
pkg_version() { v=${1##*-}; echo "${v%.pkg}"; }
if [ -n "${DEV_REPO_URL}" ]; then
    DEV="${SELF}/repo-dev/${ABI}"
    rm -rf "${DEV}"; mkdir -p "${DEV}"
    cp "${STAGE}"/*.pkg "${DEV}/" 2>/dev/null || true
    tmp=$(mktemp -d)
    if fetch -qo "${tmp}/packagesite.pkg" "${DEV_REPO_URL}/${ABI}/packagesite.pkg" 2>/dev/null; then
        tar -xf "${tmp}/packagesite.pkg" -C "${tmp}" packagesite.yaml
        sed -n 's/.*"repopath":"\([^"]*\)".*/\1/p' "${tmp}/packagesite.yaml" | sort -u |
        while read -r path; do
            file=$(basename "${path}")
            mine=$(ls "${DEV}/${file%-*}"-*.pkg 2>/dev/null | head -1)
            if [ -n "${mine}" ]; then
                [ "$(pkg version -t "$(pkg_version "${file}")" "$(pkg_version "${mine}")")" = ">" ] ||
                    continue  # this build is at least as new
                rm -f "${mine}"
            fi
            fetch -qo "${DEV}/${file}" "${DEV_REPO_URL}/${ABI}/${path}" || rm -f "${DEV}/${file}"
        done
    fi
    rm -rf "${tmp}"
    pkg repo "${DEV}" ${REPO_SIGNING_KEY:+"${REPO_SIGNING_KEY}"}
fi

rm -rf "${STAGE}"
