#!/bin/sh

# Run every plugin's regression tests: the Python unittest modules and PHP scripts in
# */*/tests. PHP tests load core's classes from the checkout named by OPNSENSE_CORE.

ROOT=$(cd "$(dirname "$0")/.." && pwd)
PYTHON=${PYTHON:-python3}
STATUS=0

for DIR in "${ROOT}"/*/*/tests; do
	[ -d "${DIR}" ] || continue
	echo "== ${DIR#"${ROOT}"/}"
	if ls "${DIR}"/test_*.py > /dev/null 2>&1; then
		"${PYTHON}" -m unittest discover -s "${DIR}" -p 'test_*.py' || STATUS=1
	fi
	for SCRIPT in "${DIR}"/*_test.php; do
		[ -f "${SCRIPT}" ] || continue
		php -d error_reporting=E_ALL "${SCRIPT}" || STATUS=1
	done
done

exit ${STATUS}
