#!/bin/sh
# Build a blocky binary package from the FreeBSD port, pinned to $1 (upstream
# version); output pkg into $2. Invoked by the build workflow.
#
# The port supplies the packaging the plugin needs.
set -e

VERSION="$1"
OUT="$2"
PORT="${PORTSDIR:-/usr/ports}/dns/blocky"

mkdir -p "${OUT}"

# Route blocky's stdout/stderr to syslog (program "blocky") instead of a flat
# /var/log/blocky.log, so it integrates with OPNsense's log viewer and log
# rotation. blocky has no native syslog output, so we bridge it via daemon(8)'s
# -T (syslog tag) in the port's rc script.
RC_IN="${PORT}/files/blocky.in"
# a silent no-match would ship a package whose log never reaches syslog
if ! grep -qF -- '-o ${logfile}' "${RC_IN}"; then
    echo "${RC_IN} no longer logs to \${logfile}; the syslog bridge needs updating" >&2
    exit 1
fi
sed -i '' -e 's#-o \${logfile}#-T \${name}#' "${RC_IN}"

make -C "${PORT}" DISTVERSION="${VERSION}" clean makesum package
find "${PORT}/work" -name 'blocky-*.pkg' -exec cp {} "${OUT}/" \;
