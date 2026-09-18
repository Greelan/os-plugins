#!/bin/sh
# Fail when a plugin's installed files (src/, including the lib/VENDOR pins) changed
# between commits $1 and $2 but its PLUGIN_VERSION/PLUGIN_REVISION did not, so no
# change ships under an existing version. Invoked by the build workflow on push.
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
    git diff --quiet "${BEFORE}" "${AFTER}" -- "${DIR}/src" && continue
    if [ "$(version "${BEFORE}" "${MK}")" = "$(version "${AFTER}" "${MK}")" ]; then
        echo "${DIR}: src/ changed but PLUGIN_VERSION/PLUGIN_REVISION did not" >&2
        STATUS=1
    fi
done
exit ${STATUS}
