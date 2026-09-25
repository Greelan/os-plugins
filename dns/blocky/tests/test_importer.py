"""The config.yml importer takes only what the model allows, and says what it left out."""

import json
import os
import subprocess
import sys
import tempfile
import unittest

IMPORTER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src", "opnsense", "scripts",
                        "OPNsense", "Blocky", "import_config.py")
BASE = "upstreams:\n  groups:\n    default: [1.1.1.1]\n"


def run(yml):
    with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False) as handle:
        handle.write(BASE + yml)
    try:
        answer = subprocess.run([sys.executable, IMPORTER, handle.name], capture_output=True, text=True, check=True)
    finally:
        os.unlink(handle.name)
    return json.loads(answer.stdout)


def warned(result, text):
    return any(text in warning for warning in result["warnings"])


class Importer(unittest.TestCase):
    def test_list_files_only_from_the_list_directory(self):
        result = run("blocking:\n  denylists:\n    ads:\n      - https://example.com/list.txt\n"
                     "      - /etc/master.passwd\n      - /usr/local/etc/blocky/lists/mine.txt\n"
                     "hostsFile:\n  sources: [/etc/hosts, /root/hosts]\n")
        self.assertEqual([row["source"] for row in result["arrays"]["denylists"]],
                         ["https://example.com/list.txt", "/usr/local/etc/blocky/lists/mine.txt"])
        self.assertEqual(result["scalars"]["hostsFile"]["sources"], "/etc/hosts")
        self.assertTrue(warned(result, "/etc/master.passwd is a file outside"))
        self.assertTrue(warned(result, "/root/hosts is a file other than /etc/hosts"))

    def test_fixed_write_paths(self):
        result = run("blocking:\n  loading:\n    downloads:\n      cachePath: /tmp/cache\n"
                     "queryLog:\n  type: csv\n  target: /tmp/logs\n")
        self.assertEqual(result["scalars"]["general"]["downloadCache"], "1")
        self.assertNotIn("target", result["scalars"]["queryLog"])
        self.assertTrue(warned(result, "the cache is kept in /var/cache/blocky/lists"))
        self.assertTrue(warned(result, "written to /var/db/blocky/querylog"))

    def test_certificate_paths_are_not_taken(self):
        result = run("certFile: /etc/ssl/a.pem\nkeyFile: /etc/ssl/a.key\n")
        self.assertNotIn("certFile", result["scalars"].get("general", {}))
        self.assertTrue(warned(result, "certFile: import the certificate under System: Trust"))

    def test_secrets_only_from_the_secrets_directory(self):
        result = run("redis:\n  address: r:6379\n  password: file:/etc/master.passwd\n"
                     "  sentinelPassword: file:/usr/local/etc/blocky/secrets/sentinel\n")
        self.assertNotIn("password", result["scalars"]["redis"])
        self.assertEqual(result["scalars"]["redis"]["sentinelPassword"], "file:/usr/local/etc/blocky/secrets/sentinel")

    def test_nothing_read_or_connected_to_from_free_text(self):
        result = run("customDNS:\n  zone: |\n    $TTL 3600\n    $INCLUDE /etc/master.passwd\n    h.lan. IN A 10.0.0.1\n"
                     "bootstrapDns:\n  - resolvFile: /etc/resolv.conf\n"
                     "redis:\n  address: /var/run/configd.socket\n  sentinelAddresses: [/var/run/s.sock, s1:26379]\n"
                     "queryLog:\n  type: dnstap\n  target: unix:/var/run/configd.socket\n")
        self.assertNotIn("$INCLUDE", result["scalars"]["general"]["customZone"])
        self.assertNotIn("bootstrap", result["arrays"])
        self.assertNotIn("address", result["scalars"]["redis"])
        self.assertEqual(result["scalars"]["redis"]["sentinelAddresses"], "s1:26379")
        self.assertEqual(result["scalars"]["queryLog"]["type"], "none")

    def test_the_redis_plugin_socket_is_allowed(self):
        result = run("redis:\n  address: /var/run/redis/redis.sock\n")
        self.assertEqual(result["scalars"]["redis"]["address"], "/var/run/redis/redis.sock")


if __name__ == "__main__":
    unittest.main()
