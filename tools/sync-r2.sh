#!/bin/sh
# Sync the built repositories to R2: prod at the bucket root, the dev channel under dev/. Each
# FreeBSD major is synced on its own, with --delete inside it only, so a major not built in this
# run (frozen) stays as published. Usage: sync-r2.sh dev|prod|both. Invoked by the build workflow.
set -e

cd "$(dirname "$0")/.."
# everything revalidates: pages and repository metadata keep their names
CACHE=${CACHE:-"public, max-age=60, must-revalidate"}

# local directory, remote prefix, then anything more for aws s3 sync
sync_dir()
{
	local from to
	from=$1
	to=$2
	shift 2
	aws s3 sync "${from}" "s3://${R2_BUCKET}/${to}" --endpoint-url "${R2_ENDPOINT}" --delete "$@" \
	    --cache-control "${CACHE}" --no-progress
}

sync_prod()
{
	local dir
	for dir in repo/FreeBSD:*/; do
		[ -d "${dir}" ] || continue
		sync_dir "${dir}" "$(basename "${dir}")/"
	done
	sync_dir repo/ "" --exclude "dev/*" --exclude "FreeBSD:*"
}

sync_dev()
{
	local dir
	if ! ls repo-dev/*/*.pkg >/dev/null 2>&1; then
		echo "no dev repository was built; leaving the channel alone"
		return 0
	fi
	for dir in repo-dev/FreeBSD:*/; do
		[ -d "${dir}" ] || continue
		sync_dir "${dir}" "dev/$(basename "${dir}")/"
	done
}

case "$1" in
dev) sync_dev ;;
prod) sync_prod ;;
both) sync_prod; sync_dev ;;
*) echo "usage: $0 dev|prod|both" >&2; exit 1 ;;
esac
