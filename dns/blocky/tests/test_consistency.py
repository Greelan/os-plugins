"""The importer (Python) and the model (PHP) must agree on which files and secrets are allowed."""

import importlib.util
import json
import os
import subprocess
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPTS = os.path.join(HERE, "..", "src", "opnsense", "scripts", "OPNsense", "Blocky")
SOURCES = ["https://example.com/l.txt", "ads.example.com", "/^ad[sx]?\\./", "/usr/local/etc/blocky/lists/mine.txt",
           "/usr/local/etc/blocky/lists/sub/mine.txt", "file:///usr/local/etc/blocky/lists/mine.txt",
           "/usr/local/etc/blocky/lists/", "/usr/local/etc/blocky/lists/../config.yml",
           "/usr/local/etc/blocky/lists//x", "/etc/master.passwd", "file:///etc/master.passwd", "/etc/hosts",
           "FILE:///etc/master.passwd"]
SECRETS = ["hunter2", "FILE:/etc/master.passwd", "file:/etc/master.passwd", "file:///etc/master.passwd",
           "file:/usr/local/etc/blocky/secrets/redis", "file:///usr/local/etc/blocky/secrets/redis",
           "file://usr/local/etc/blocky/secrets/redis", "file:/usr/local/etc/blocky/secrets/../config.yml",
           "file:/usr/local/etc/blocky/secrets/", "file:/usr/local/etc/blocky/secrets/a/b", "myfile:/x"]
PHP = """<?php
require '%s';
$cases = json_decode($argv[1], true);
echo json_encode([
    'sources' => array_map(fn($s) => [OPNsense\\Blocky\\Blocky::isAllowedFile($s),
        OPNsense\\Blocky\\Blocky::isAllowedFile($s, OPNsense\\Blocky\\Blocky::HOSTS_FILES)], $cases['sources']),
    'secrets' => array_map(fn($s) => OPNsense\\Blocky\\Blocky::isAllowedSecret($s), $cases['secrets']),
]) . "\n";
$GLOBALS['test_checks'] = 1;
""" % os.path.join(HERE, "..", "..", "..", "tools", "tests", "bootstrap.php")


@unittest.skipUnless(os.environ.get("OPNSENSE_CORE"), "needs OPNSENSE_CORE for the model")
class Consistency(unittest.TestCase):
    def test_same_answers(self):
        spec = importlib.util.spec_from_file_location("import_config", os.path.join(SCRIPTS, "import_config.py"))
        importer = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(importer)
        answer = subprocess.run(["php", "-r", PHP.replace("<?php\n", ""), "--",
                                 json.dumps({"sources": SOURCES, "secrets": SECRETS})],
                                capture_output=True, text=True, check=True)
        php = json.loads(answer.stdout.splitlines()[0])
        python_sources = [[importer.allowed_file(s), importer.allowed_file(s, ("/etc/hosts",))] for s in SOURCES]
        self.assertEqual(dict(zip(SOURCES, php["sources"])), dict(zip(SOURCES, python_sources)))
        self.assertEqual(dict(zip(SECRETS, php["secrets"])),
                         {s: importer.allowed_secret(s) for s in SECRETS})


if __name__ == "__main__":
    unittest.main()
