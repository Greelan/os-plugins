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

pkg repo "${OUT}" ${REPO_SIGNING_KEY:+"${REPO_SIGNING_KEY}"}

# site root: pkg client config (landing/changelog built at deploy by build-site.sh)
cp "${SELF}/tools/greelan.conf" "${SELF}/repo/greelan.conf"
