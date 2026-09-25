#!/bin/sh
# Fail when what a plugin's package is built from (src/, including the lib/VENDOR pins,
# its Makefile, pkg-descr and package scripts) changed between commits $1 and $2 but its
# PLUGIN_VERSION/PLUGIN_REVISION did not: the build reuses a published version as it is,
# so the change would never ship. Likewise for how the blocky binary is built. Invoked by
# the build workflow on push.
set -e

BEFORE="$1"
AFTER="$2"
cd "$(dirname "$0")/.."

if ! git cat-file -e "${BEFORE}^{commit}" 2>/dev/null; then
    echo "previous commit ${BEFORE} is not in the history (force push?); deploy with a manual run" >&2
    exit 1
fi

version() {
    git show "$1:$2" 2>/dev/null | grep -E '^PLUGIN_(VERSION|REVISION)=' || true
}

STATUS=0
for MK in */*/Makefile; do
    grep -q 'Mk/plugins.mk' "${MK}" || continue
    DIR=$(dirname "${MK}")
    git diff --quiet "${BEFORE}" "${AFTER}" -- "${DIR}" ":(exclude)${DIR}/CHANGELOG.md" \
        ":(exclude)${DIR}/tests" ":(exclude)${DIR}/BLOCKY_VERSION" && continue
    if [ "$(version "${BEFORE}" "${MK}")" = "$(version "${AFTER}" "${MK}")" ]; then
        echo "${DIR}: the package's files changed but PLUGIN_VERSION/PLUGIN_REVISION did not" >&2
        STATUS=1
    fi
done
if ! git diff --quiet "${BEFORE}" "${AFTER}" -- tools/build-blocky-port.sh &&
    git diff --quiet "${BEFORE}" "${AFTER}" -- dns/blocky/BLOCKY_VERSION; then
    echo "tools/build-blocky-port.sh changed but the blocky version did not; the published" \
        "package would be kept, so rebuild it with a forced manual run" >&2
    STATUS=1
fi
exit ${STATUS}
