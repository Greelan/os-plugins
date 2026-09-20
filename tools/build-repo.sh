#!/bin/sh
# Build every plugin (and, if BLOCKY_PKG_DIR is set, the blocky binary) into a
# per-ABI pkg repository at repo/<ABI>/. Invoked by the build workflow.
set -e

SELF=$(cd "$(dirname "$0")/.." && pwd)
ABI=$(pkg config abi)
OUT="${SELF}/repo/${ABI}"
rm -rf "${OUT}"; mkdir -p "${OUT}"

# each <category>/<name>/ carrying a plugin Makefile
for mk in "${SELF}"/*/*/Makefile; do
    grep -q 'Mk/plugins.mk' "${mk}" 2>/dev/null || continue
    pdir=$(dirname "${mk}")
    make -C "${pdir}" package
    find "${pdir}/work" -name '*.pkg' -exec cp {} "${OUT}/" \;
done

# blocky binary, built separately by build-blocky-port.sh
[ -n "${BLOCKY_PKG_DIR}" ] && cp "${BLOCKY_PKG_DIR}"/blocky-*.pkg "${OUT}/" 2>/dev/null || true

# Testing channel: layer this build onto what the channel already holds, so building one
# branch never withdraws a package another branch published. Newest version of each name
# wins, whichever side it came from; without this the repo is one branch's snapshot.
pkg_version() { v=${1##*-}; echo "${v%.pkg}"; }
if [ -n "${MERGE_REPO_URL}" ]; then
    tmp=$(mktemp -d)
    if fetch -qo "${tmp}/packagesite.pkg" "${MERGE_REPO_URL}/${ABI}/packagesite.pkg" 2>/dev/null; then
        tar -xf "${tmp}/packagesite.pkg" -C "${tmp}" packagesite.yaml
        sed -n 's/.*"repopath":"\([^"]*\)".*/\1/p' "${tmp}/packagesite.yaml" | sort -u |
        while read -r path; do
            file=$(basename "${path}")
            mine=$(ls "${OUT}/${file%-*}"-*.pkg 2>/dev/null | head -1)
            if [ -n "${mine}" ]; then
                [ "$(pkg version -t "$(pkg_version "${file}")" "$(pkg_version "${mine}")")" = ">" ] ||
                    continue  # this build is at least as new
                rm -f "${mine}"
            fi
            fetch -qo "${OUT}/${file}" "${MERGE_REPO_URL}/${ABI}/${path}" || rm -f "${OUT}/${file}"
        done
    fi
    rm -rf "${tmp}"
fi

pkg repo "${OUT}" ${REPO_SIGNING_KEY:+"${REPO_SIGNING_KEY}"}

# site root: pkg client config (landing/changelog built at deploy by build-site.sh)
cp "${SELF}/tools/greelan.conf" "${SELF}/repo/greelan.conf"
