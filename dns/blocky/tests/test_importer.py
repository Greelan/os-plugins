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

    def test_text_keeps_its_spelling(self):
        # blocky's yaml.v2 reads a string field as written; YAML 1.1 would make numbers of these
        result = run("redis:\n  address: r:6379\n  username: 007\n  password: 0000\n  sentinelPassword: 1.10\n"
                     "blocking:\n  clientGroupsBlock:\n    on: [ads]\n")
        self.assertEqual([result["scalars"]["redis"][k] for k in ("username", "password", "sentinelPassword")],
                         ["007", "0000", "1.10"])
        self.assertEqual(result["arrays"]["clientgroups"][0]["client"], "on")
        self.assertEqual(result["warnings"], [])
        self.assertEqual(run("ports:\n  dns: 53\nprometheus:\n  enable: yes\n")["scalars"]["general"]["prometheus"], "1")

    def test_values_blocky_takes_fit_the_fields(self):
        result = run("blocking:\n  blockTTL: 0\n  schedules:\n    work:\n      weekdays: [Mon, Tue]\n      start: 09:00\n"
                     "      end: 17:00\n  listSchedules:\n    ads: [work]\n  denylists:\n    ads: [ads.lan]\n"
                     "upstreams:\n  timeout: 1.5s\nlog:\n  level: WARNING\nminTlsServeVersion: 1.1\n"
                     "caching:\n  minTime: 2.25h\n  maxTime: 0\n  cacheTimeNegative: .5s\n")
        general = result["scalars"]["general"]
        self.assertEqual((general["blockTTL"], general["timeout"], general["cacheMinTime"], general["cacheMaxTime"],
                          general["cacheTimeNegative"]),
                         ("0m", "1s500ms", "2h15m", "0", "500ms"), "a bare 0 stays where the field takes it")
        self.assertEqual(result["arrays"]["schedules"][0]["weekdays"], "mon,tue")
        self.assertEqual((general["logLevel"], general["minTlsServeVersion"]), ("warn", "1.2"))
        self.assertTrue(warned(result, "TLS 1.2"))

    def test_hosts_entries_as_blocky_reads_them(self):
        result = run("hostsFile:\n  sources:\n    - |\n      10.0.0.1\tprinter.lan\n      10.0.0.2  nas.lan\n"
                     "    - /etc/hosts\nblocking:\n  denylists:\n    ads: ['0.0.0.0\tads.lan']\n")
        self.assertEqual(result["scalars"]["hostsFile"]["sources"], "10.0.0.1 printer.lan,10.0.0.2  nas.lan,/etc/hosts",
                         "a tab becomes a space, spaces stay as they are")
        self.assertEqual(result["arrays"]["denylists"][0]["source"], "0.0.0.0 ads.lan")

    def test_an_empty_key_is_left_to_the_default(self):
        result = run("ports:\n  dns: \"\"\nblocking:\n  blockTTL: \"\"\n  loading:\n    refreshPeriod: \"\"\n")
        self.assertNotIn("general", result["scalars"])

    def test_an_odd_date_is_text(self):
        self.assertNotIn("error", run("upstreams:\n  userAgent: 2026-13-45\n"))


if __name__ == "__main__":
    unittest.main()
