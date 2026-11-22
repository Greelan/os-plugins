"""The staged config.yml replaces the live one only when Blocky takes it: a refused one is kept out,
with Blocky's reason in the log, and configtest answers with that reason or nothing. Apply discards
the live one when it refuses the staged one while Blocky is stopped, so a later start cannot run it."""

import configparser
import os
import re
import shutil
import subprocess
import tempfile
import unittest

SRC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src", "opnsense")
SCRIPT = os.path.join(SRC, "scripts", "OPNsense", "Blocky", "deploy.sh")
ACTIONS = os.path.join(SRC, "service", "conf", "actions.d", "actions_blocky.conf")
SERVICE = os.path.join(SRC, "mvc", "app", "controllers", "OPNsense", "Blocky", "Api", "ServiceController.php")
BLOCKY = os.environ.get("BLOCKY") or shutil.which("blocky")
GOOD = "upstreams:\n  groups:\n    default: [1.1.1.1]\n"


@unittest.skipUnless(BLOCKY, "needs blocky")
class Deploy(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.folder)
        self.config = os.path.join(self.folder, "config.yml")
        self.log = os.path.join(self.folder, "log")
        with open(SCRIPT) as handle:
            script = handle.read()
        for fixed, ours in (("/usr/local/sbin/blocky", BLOCKY), ("/usr/local/etc/blocky/config.yml", self.config),
                            ("logger -t blocky -p daemon.err", "echo >> %s" % self.log)):
            self.assertIn(fixed, script)
            script = script.replace(fixed, ours)
        self.script = os.path.join(self.folder, "deploy.sh")
        with open(self.script, "w") as handle:
            handle.write(script)

    def run_script(self, *args):
        return subprocess.run(["sh", self.script, *args], capture_output=True, text=True, check=True).stdout

    def write(self, name, text):
        with open(os.path.join(self.folder, name), "w") as handle:
            handle.write(text)

    def read(self, name):
        with open(os.path.join(self.folder, name)) as handle:
            return handle.read()

    def test_taken_config_goes_live(self):
        self.write("config.yml", GOOD)
        self.write("config.yml.staging", GOOD.replace("1.1.1.1", "9.9.9.9"))
        self.assertEqual(self.run_script(), "")
        self.run_script("deploy")
        self.assertIn("9.9.9.9", self.read("config.yml"))
        self.assertFalse(os.path.exists(self.log))

    def test_refused_config_stays_out_with_the_whole_reason(self):
        self.write("config.yml", GOOD)
        self.write("config.yml.staging", GOOD + "caching:\n  maxItemsCount: abc\n")
        refusal = self.run_script().strip()
        # the reason Blocky gives over several lines, without the path to the staged file
        self.assertTrue(refusal.startswith("Error: yaml: unmarshal errors: "), refusal)
        self.assertIn("caching.maxItemsCount: got string, want integer", refusal)
        self.assertNotIn("staging", refusal)
        self.run_script("deploy")
        self.assertEqual(self.read("config.yml"), GOOD)
        self.assertIn("keeps the one it has: yaml: unmarshal errors:", self.read("log"))

    def test_a_zone_refusal_says_it_is_the_zone(self):
        self.write("config.yml.staging", GOOD + "customDNS:\n  zone: |\n    h.lan. 60 IN HTTPS 1 . foo=bar\n")
        self.assertTrue(self.run_script().startswith("Error: zone file parsing error: dns: bad SVCB key"))

    def test_a_crash_is_a_refusal(self):
        crash = os.path.join(self.folder, "crash")
        with open(crash, "w") as handle:
            handle.write("#!/bin/sh\necho 'panic: runtime error' >&2\nexit 2\n")
        os.chmod(crash, 0o755)
        with open(self.script) as handle:
            script = handle.read().replace(BLOCKY, crash)
        with open(self.script, "w") as handle:
            handle.write(script)
        self.write("config.yml", GOOD)
        self.write("config.yml.staging", GOOD.replace("1.1.1.1", "9.9.9.9"))
        self.assertEqual(self.run_script().strip(), "Error: blocky validate failed (exit 2)")
        self.run_script("deploy")
        self.assertEqual(self.read("config.yml"), GOOD)
        self.assertEqual([n for n in os.listdir(self.folder) if n.startswith("config.yml.")], ["config.yml.staging"])

    def test_a_missing_resolv_file(self):
        # Blocky reads it only once it serves, and exits without it
        resolv = os.path.join(self.folder, "it's resolv.conf")
        staged = GOOD + "bootstrapDns:\n  - resolvFile: '%s'\n" % resolv.replace("'", "''")
        self.write("config.yml", GOOD)
        self.write("config.yml.staging", staged)
        self.assertEqual(self.run_script().strip(), "Error: the bootstrap resolv file %s does not exist" % resolv)
        self.run_script("deploy")
        self.assertEqual(self.read("config.yml"), GOOD)
        self.write(os.path.basename(resolv), "nameserver 1.1.1.1\n")
        self.assertEqual(self.run_script(), "")
        self.run_script("deploy")
        self.assertEqual(self.read("config.yml"), staged)

    def test_nothing_staged(self):
        self.assertEqual(self.run_script(), "")
        self.run_script("deploy")
        self.assertFalse(os.path.exists(self.config))

    def test_refused_with_none_in_place(self):
        self.write("config.yml.staging", GOOD + "caching:\n  maxItemsCount: abc\n")
        self.run_script("deploy")
        self.assertFalse(os.path.exists(self.config))
        self.assertIn("so Blocky has none to start with: yaml: unmarshal errors:", self.read("log"))


class Discard(unittest.TestCase):
    def test_discard_removes_what_deploy_puts_in_place(self):
        conf = configparser.ConfigParser(interpolation=None)
        conf.read(ACTIONS)
        with open(SCRIPT) as handle:
            live = re.search(r"^CONFIG=(\S+)$", handle.read(), re.M).group(1)
        self.assertEqual(conf["discard"]["command"], "/bin/rm -f %s" % live)

    def test_apply_discards_only_when_it_refuses_while_blocky_is_stopped(self):
        with open(SERVICE) as handle:
            text = handle.read()
        refused = text.index("if (strpos($refusal, 'Error: ') === 0) {")
        # an unknown status may be a running Blocky, which must keep what it would restart with
        stopped = text.index("if ($this->statusAction()['status'] === 'stopped') {", refused)
        self.assertLess(stopped, text.index("configdRun('blocky discard')", refused))
        self.assertLess(text.index("configdRun('blocky discard')"), text.index("return ['status' => 'failed'"))
        self.assertEqual(text.count("blocky discard"), 1)


if __name__ == "__main__":
    unittest.main()
