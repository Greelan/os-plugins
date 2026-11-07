"""tools/sync-r2.sh against a stub aws that logs each call."""

import os
import shutil
import subprocess
import tempfile
import unittest

SCRIPT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "sync-r2.sh")
CACHE = "public, max-age=60, must-revalidate"
STUB = """#!/bin/sh
for arg in "$@"; do printf '%s\\t' "$arg"; done >> "$AWS_LOG"
echo >> "$AWS_LOG"
"""


class SyncR2(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = self.root = self.tmp.name
        os.makedirs(os.path.join(root, "tools"))
        shutil.copy(SCRIPT, os.path.join(root, "tools", "sync-r2.sh"))
        for path in ("repo/FreeBSD:15:amd64/x.pkg", "repo/greelan.conf", "repo/index.html",
                     "repo-dev/FreeBSD:15:amd64/x.pkg"):
            os.makedirs(os.path.dirname(os.path.join(root, path)), exist_ok=True)
            open(os.path.join(root, path), "w").close()
        os.makedirs(os.path.join(root, "bin"))
        with open(os.path.join(root, "bin", "aws"), "w") as stub:
            stub.write(STUB)
        os.chmod(os.path.join(root, "bin", "aws"), 0o755)
        self.log = os.path.join(root, "aws.log")

    def tearDown(self):
        self.tmp.cleanup()

    def sync(self, channel):
        env = dict(os.environ, PATH=os.path.join(self.root, "bin") + os.pathsep + os.environ["PATH"],
                   AWS_LOG=self.log, R2_BUCKET="b", R2_ENDPOINT="e")
        env.pop("CACHE", None)
        result = subprocess.run(["sh", os.path.join(self.root, "tools", "sync-r2.sh"), channel],
                                capture_output=True, text=True, cwd="/", env=env)
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = []
        if os.path.exists(self.log):
            calls = [line.rstrip("\n").split("\t")[:-1] for line in open(self.log)]
        return result, calls

    @staticmethod
    def major(local, remote):
        return ["s3", "sync", local, remote, "--endpoint-url", "e", "--delete",
                "--cache-control", CACHE, "--no-progress"]

    def test_prod_syncs_each_major_then_the_root(self):
        _, calls = self.sync("prod")
        self.assertEqual(calls, [
            self.major("repo/FreeBSD:15:amd64/", "s3://b/FreeBSD:15:amd64/"),
            ["s3", "sync", "repo/", "s3://b/", "--endpoint-url", "e", "--delete", "--exclude", "dev/*",
             "--exclude", "FreeBSD:*", "--cache-control", CACHE, "--no-progress"],
        ])

    def test_dev_syncs_each_major_under_dev(self):
        _, calls = self.sync("dev")
        self.assertEqual(calls, [self.major("repo-dev/FreeBSD:15:amd64/", "s3://b/dev/FreeBSD:15:amd64/")])

    def test_dev_without_packages_leaves_the_channel_alone(self):
        os.remove(os.path.join(self.root, "repo-dev", "FreeBSD:15:amd64", "x.pkg"))
        result, calls = self.sync("dev")
        self.assertEqual(calls, [])
        self.assertIn("no dev repository was built; leaving the channel alone", result.stdout)

    def test_unbuilt_major_is_never_named(self):
        _, calls = self.sync("both")
        self.assertEqual(len(calls), 3)
        self.assertFalse([call for call in calls if any("FreeBSD:14" in arg for arg in call)])
        root = [call for call in calls if call[2] == "repo/"]
        self.assertEqual(len(root), 1)
        self.assertEqual(root[0][root[0].index("FreeBSD:*") - 1], "--exclude")


if __name__ == "__main__":
    unittest.main()
