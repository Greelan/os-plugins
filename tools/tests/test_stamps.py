"""tools/stamps.subr against a stub pkg that reads each package's FreeBSD_version from a sidecar file."""

import os
import subprocess
import tempfile
import unittest

STAMPS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "stamps.subr")
STUB = """#!/bin/sh
# pkg query -F <file> '%At %Av'
[ "$(cat "$3.stamp" 2>/dev/null)" = unreadable ] && exit 1
echo "repo_type binary"
[ -f "$3.stamp" ] && echo "FreeBSD_version $(cat "$3.stamp")"
exit 0
"""


class Stamps(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = os.path.join(self.tmp.name, "repo")
        os.mkdir(self.dir)
        self.pkg = os.path.join(self.tmp.name, "pkg")
        with open(self.pkg, "w") as stub:
            stub.write(STUB)
        os.chmod(self.pkg, 0o755)

    def tearDown(self):
        self.tmp.cleanup()

    def package(self, name, stamp=None):
        path = os.path.join(self.dir, name)
        open(path, "w").close()
        if stamp is not None:
            with open(path + ".stamp", "w") as sidecar:
                sidecar.write(stamp)
        return path

    def run_function(self, *args):
        return subprocess.run(["sh", "-c", '. "$STAMPS"; "$@"', "sh", *args], capture_output=True, text=True,
                              cwd=self.tmp.name, env=dict(os.environ, STAMPS_PKG=self.pkg, STAMPS=STAMPS))

    def test_reads_the_stamp(self):
        path = self.package("blocky-0.35.0_5.pkg", "1405000")
        result = self.run_function("pkg_stamp", path)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "1405000")

    def test_missing_stamp_passes(self):
        self.package("os-notify-greelan-1.7_1.pkg")
        self.assertEqual(self.run_function("stamps_check", "1403000", self.dir).returncode, 0)

    def test_equal_and_below_pass(self):
        self.package("a.pkg", "1403000")
        self.package("b.pkg", "1401000")
        result = self.run_function("stamps_check", "1403000", self.dir)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_above_base_fails_and_names_it(self):
        self.package("blocky-0.35.0_5.pkg", "1405000")
        result = self.run_function("stamps_check", "1403000", self.dir)
        self.assertEqual(result.returncode, 1)
        for text in ("blocky-0.35.0_5.pkg", "1405000", "1403000"):
            self.assertIn(text, result.stderr)

    def test_non_numeric_stamp_fails(self):
        self.package("a.pkg", "14.5")
        result = self.run_function("stamps_check", "1403000", self.dir)
        self.assertEqual(result.returncode, 1)
        self.assertIn("a.pkg: built for 14.5", result.stderr)

    def test_unreadable_package_fails(self):
        self.package("a.pkg", "unreadable")
        result = self.run_function("stamps_check", "1403000", self.dir)
        self.assertEqual(result.returncode, 1)
        self.assertIn("a.pkg: built for (unreadable)", result.stderr)

    def test_empty_stamp_fails(self):
        self.package("a.pkg", "")
        result = self.run_function("stamps_check", "1403000", self.dir)
        self.assertEqual(result.returncode, 1)
        self.assertIn("a.pkg: built for -", result.stderr)

    def test_zero_stamp_fails(self):
        self.package("a.pkg", "0")
        self.assertEqual(self.run_function("stamps_check", "1403000", self.dir).returncode, 1)

    def test_a_stray_pkg_variable_is_not_used(self):
        self.package("a.pkg", "1405000")
        env = dict(os.environ, PKG="/nonexistent", STAMPS_PKG=self.pkg, STAMPS=STAMPS)
        result = subprocess.run(["sh", "-c", '. "$STAMPS"; stamps_check 1403000 "$1"', "sh", self.dir],
                                capture_output=True, text=True, env=env)
        self.assertEqual(result.returncode, 1)
        self.assertIn("built for 1405000", result.stderr)


if __name__ == "__main__":
    unittest.main()
