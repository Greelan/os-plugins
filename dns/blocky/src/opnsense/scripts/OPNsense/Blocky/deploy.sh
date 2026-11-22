#!/bin/sh

# Blocky reads config.yml only when it starts. The template writes config.yml.staging, which
# replaces config.yml only when Blocky can read it, so a configuration Blocky would refuse to read
# never replaces the one it last started with. What fails only once Blocky serves, such as a
# listener on an address the firewall does not have, is not caught, except a missing bootstrap resolv
# file. Without an argument, print why the staged configuration would not be put in place, or nothing;
# with "deploy", put it in place, or log why not.

BLOCKY=/usr/local/sbin/blocky
CONFIG=/usr/local/etc/blocky/config.yml
STAGING=${CONFIG}.staging

[ -f "${STAGING}" ] || exit 0

# a copy of its own, which a render running meanwhile cannot change, is checked and put in place
COPY=$(mktemp "${CONFIG}.deploy.XXXXXX")
trap 'rm -f "${COPY}"' EXIT

if [ -z "${COPY}" ] || ! cp "${STAGING}" "${COPY}" || [ ! -s "${COPY}" ]; then
	STATUS=1
	REASON="Error: the staged configuration could not be copied"
else
	# the verdict goes to stderr, progress to stdout
	REASON=$(${BLOCKY} validate --config "${COPY}" 2>&1 > /dev/null)
	STATUS=$?
	# an error can go on over further lines, e.g. one per value YAML cannot take; the copy's
	# path and the wrapping around Blocky's own words are left out
	REASON=$(echo "${REASON}" | sed -n '/^Error: /,$p' | sed 's/^[[:space:]]*//' | paste -s -d ' ' - |
	    sed -e "s#'*${COPY}'*: ##g" -e 's#unable to load configuration file ##' \
	    -e 's#failed to unmarshal config from ##' -e 's#wrong file structure: ##')
	# a crash or a kill says nothing of its own
	if [ ${STATUS} -ne 0 ] && [ -z "${REASON}" ]; then
		REASON="Error: blocky validate failed (exit ${STATUS})"
	fi
fi

# Blocky reads a bootstrap resolv file only once it serves, and exits when it is missing; the
# template writes each on a line of its own, quoted as any value
if [ ${STATUS} -eq 0 ]; then
	MISSING=$(sed -n "s/^  - resolvFile: '\(.*\)'\$/\1/p" "${COPY}" | sed "s/''/'/g" |
	    while IFS= read -r FILE; do [ -f "${FILE}" ] || echo "${FILE}"; done | head -n 1)
	if [ -n "${MISSING}" ]; then
		STATUS=1
		REASON="Error: the bootstrap resolv file ${MISSING} does not exist"
	fi
fi

if [ "${1}" != "deploy" ]; then
	[ ${STATUS} -eq 0 ] || echo "${REASON}"
elif [ ${STATUS} -ne 0 ] && [ -f "${CONFIG}" ]; then
	logger -t blocky -p daemon.err "The new configuration was not put in place, Blocky keeps the one it has: ${REASON#Error: }"
elif [ ${STATUS} -ne 0 ]; then
	# none since the install, or discarded when Apply refused the staged one while Blocky was stopped
	logger -t blocky -p daemon.err "The new configuration was not put in place, so Blocky has none to start with: ${REASON#Error: }"
elif ! chmod 0640 "${COPY}" || ! mv -f "${COPY}" "${CONFIG}"; then
	logger -t blocky -p daemon.err "The new configuration could not be put in place; Blocky keeps the one it has"
fi

exit 0
