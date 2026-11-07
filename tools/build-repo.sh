#!/bin/sh
# Build every plugin, plus blocky at BLOCKY_VERSION and rclone when a plugin depends on it,
# into a per-ABI pkg repository at repo/<ABI>/. With DEV_REPO_URL set, build a second repository at repo-dev/<ABI>/
# holding the same packages layered onto what that channel already has. Invoked by the
# build workflow.
#
# A package PROD_REPO_URL already publishes under the same name and version is fetched
# from there, never rebuilt: a rebuild differs byte for byte (it records the commit), and
# a firewall that cached the published file then fails its checksum. One built for a newer
# FreeBSD than this VM's is built again: no firewall on this base could install it.
# FORCE_BUILD=1 rebuilds everything anyway.
set -e

SELF=$(cd "$(dirname "$0")/.." && pwd)
. "${SELF}/tools/stamps.subr"
ABI=$(pkg config abi)
# the FreeBSD the repository is for: nothing in it may be built for a newer one
BASE=$(uname -U)
STAGE="${SELF}/stage"
OUT="${SELF}/repo/${ABI}"
rm -rf "${STAGE}" "${OUT}"; mkdir -p "${STAGE}" "${OUT}"

# repository paths the production channel publishes, for reuse (none when forced)
PUBLISHED=$(mktemp)
if [ -z "${FORCE_BUILD}" ] && [ -n "${PROD_REPO_URL}" ]; then
    site=$(mktemp -d)
    # without the listing every package would be rebuilt and republished: stop instead
    if ! fetch -qo "${site}/packagesite.pkg" "${PROD_REPO_URL}/${ABI}/packagesite.pkg"; then
        echo "cannot read ${PROD_REPO_URL}/${ABI}; run with force for a repository's first build" >&2
        exit 1
    fi
    tar -xf "${site}/packagesite.pkg" -C "${site}" packagesite.yaml
    sed -n 's/.*"repopath":"\([^"]*\)".*/\1/p' "${site}/packagesite.yaml" > "${PUBLISHED}"
    rm -rf "${site}"
fi
# fetch the published file whose name matches $1 (an extended regex) into the stage;
# false when nothing matches, fatal when the listed file cannot be fetched
reuse() {
    path=$(grep -E "(^|/)$1\$" "${PUBLISHED}" | head -1)
    [ -n "${path}" ] || return 1
    got="${STAGE}/$(basename "${path}")"
    if ! fetch -qo "${got}" "${PROD_REPO_URL}/${ABI}/${path}"; then
        echo "cannot fetch published ${path}" >&2
        exit 1
    fi
    # built for a newer FreeBSD than this base, so no firewall on it can have installed it
    if stamp_above "${got}" "${BASE}"; then
        echo ">>> Rebuilding $(basename "${path}"): built for $(pkg_stamp "${got}"), above this base ${BASE}"
        rm -f "${got}"
        return 1
    fi
    echo ">>> Reusing published $(basename "${path}")"
}

# each <category>/<name>/ carrying a plugin Makefile
for mk in "${SELF}"/*/*/Makefile; do
    grep -q 'Mk/plugins.mk' "${mk}" 2>/dev/null || continue
    pdir=$(dirname "${mk}")
    file="$(make -C "${pdir}" -v PLUGIN_PKGNAME)-$(make -C "${pdir}" -v PLUGIN_PKGVERSION).pkg"
    reuse "$(echo "${file}" | sed 's/[.]/\\./g')" && continue
    make -C "${pdir}" package
    find "${pdir}/work" -name '*.pkg' -exec cp {} "${STAGE}/" \;
done

# rclone, when a plugin depends on it
RCLONE=
grep -h '^PLUGIN_DEPENDS' "${SELF}"/*/*/Makefile | grep -qw rclone && RCLONE=1

# ports tree: mounted on the FreeBSD 15 image, absent on 14 (never remove it)
if { [ -n "${BLOCKY_VERSION}" ] || [ -n "${RCLONE}" ]; } && [ ! -e /usr/ports/Mk/bsd.port.mk ]; then
    git clone --depth 1 https://git.FreeBSD.org/ports.git /usr/ports
fi

# blocky, from the port pinned to BLOCKY_VERSION, at the port's own revision plus
# BLOCKY_REVISION: a rebuild picks up a ports revision, and a change of ours within
# the same blocky version raises BLOCKY_REVISION (back to 0 with the next version)
if [ -n "${BLOCKY_VERSION}" ]; then
    ours=
    [ -f "${SELF}/dns/blocky/BLOCKY_REVISION" ] &&
        ours=$(tr -d ' \n' < "${SELF}/dns/blocky/BLOCKY_REVISION")
    revision=$(($(make -C /usr/ports/dns/blocky -V PORTREVISION) + ${ours:-0}))
    # pkg leaves a zero revision out of the version
    version="${BLOCKY_VERSION}"
    [ "${revision}" -eq 0 ] || version="${version}_${revision}"
    if ! reuse "blocky-$(echo "${version}" | sed 's/[.]/\\./g')\.pkg"; then
        sh "${SELF}/tools/build-blocky-port.sh" "${BLOCKY_VERSION}" "${revision}" "${STAGE}"
    fi
fi

# rclone as the port has it, version and revision: a ports bump is a rebuild
if [ -n "${RCLONE}" ]; then
    version=$(make -C /usr/ports/net/rclone -V PKGVERSION)
    if ! reuse "rclone-$(echo "${version}" | sed 's/[.]/\\./g')\.pkg"; then
        sh "${SELF}/tools/build-port.sh" net/rclone "${STAGE}"
    fi
fi
rm -f "${PUBLISHED}"

stamps_check "${BASE}" "${STAGE}"
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
                # this build wins only when newer (or forced): the channel's copy of the
                # same version stays, since firewalls may have cached it
                newer=$(pkg version -t "$(pkg_version "${file}")" "$(pkg_version "${mine}")")
                [ "${newer}" = "<" ] || { [ -n "${FORCE_BUILD}" ] && [ "${newer}" = "=" ]; } && continue
            fi
            fetch -qo "${tmp}/${file}" "${DEV_REPO_URL}/${ABI}/${path}" || { rm -f "${tmp}/${file}"; continue; }
            # this base cannot install it, so this build's copy stays, even at the same version
            if stamp_above "${tmp}/${file}" "${BASE}"; then
                echo ">>> Dropping ${file} from the channel: built for $(pkg_stamp "${tmp}/${file}"), above this base ${BASE}"
                rm -f "${tmp}/${file}"
                continue
            fi
            [ -z "${mine}" ] || rm -f "${mine}"
            mv "${tmp}/${file}" "${DEV}/${file}"
        done
    fi
    rm -rf "${tmp}"
    # e.g. another branch's package, which no firewall on this base could install
    stamps_drop_above "${BASE}" "${DEV}"
    stamps_check "${BASE}" "${DEV}"
    pkg repo "${DEV}" ${REPO_SIGNING_KEY:+"${REPO_SIGNING_KEY}"}
fi

rm -rf "${STAGE}"
