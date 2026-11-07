#!/bin/sh
# Build the port at origin $1 (e.g. net/rclone) as ports HEAD has it, unpatched, and copy its
# package into $2. Invoked by build-repo.sh.
set -e

ORIGIN="$1"
OUT="$2"
PORTS="${PORTSDIR:-/usr/ports}"
PORT="${PORTS}/${ORIGIN}"

mkdir -p "${OUT}"

# build dependencies from packages, as for blocky; BATCH keeps any options dialog from waiting
deps=$(make -C "${PORT}" build-depends-list | sed "s#^${PORTS}/##")
[ -z "${deps}" ] || pkg install -y ${deps} ||
    echo "not every build dependency of ${PORT} is packaged; the rest are built from source" >&2
make -C "${PORT}" BATCH=yes clean package
name=$(make -C "${PORT}" -V PKGNAME)
find "${PORT}/work" -name "${name}.pkg" -exec cp {} "${OUT}/" \;
if [ ! -f "${OUT}/${name}.pkg" ]; then
    echo "${PORT} built no ${name}.pkg" >&2
    exit 1
fi
