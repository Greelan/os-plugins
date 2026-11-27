"""The config.yml importer maps what blocky reads to the settings, and says what it left out."""

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
    with tempfile.TemporaryDirectory() as folder:
        path = os.path.join(folder, "blocky_import_test")
        with open(path, "w") as handle:
            handle.write(BASE + yml)
        return imported(folder, path)


def imported(folder, path):
    """The importer's answer for a path, with folder standing in for the web interface's tmp."""
    code = ("import sys; sys.path.insert(0, sys.argv.pop(1)); import import_config; "
            "import_config.TEMP_DIR = sys.argv.pop(1); import_config.main()")
    answer = subprocess.run([sys.executable, "-c", code, os.path.dirname(IMPORTER), folder, path],
                            capture_output=True, text=True, check=True)
    return json.loads(answer.stdout)


def warned(result, text):
    return any(text in warning for warning in result["warnings"])


class Importer(unittest.TestCase):
    def test_only_the_web_interface_handover_is_read(self):
        with tempfile.TemporaryDirectory() as folder, tempfile.TemporaryDirectory() as elsewhere:
            outside = os.path.join(elsewhere, "blocky_import_x")
            with open(outside, "w") as handle:
                handle.write(BASE)
            # read from the web interface's tmp by name, wherever the path points
            self.assertIn("error", imported(folder, outside))
            self.assertIn("error", imported(folder, "/etc/hosts"))
            os.symlink(outside, os.path.join(folder, "blocky_import_link"))
            self.assertIn("error", imported(folder, os.path.join(folder, "blocky_import_link")))
            with open(os.path.join(folder, "blocky_import_big"), "w") as handle:
                handle.write(BASE + "#" * (4 * 1024 * 1024))
            self.assertIn("error", imported(folder, os.path.join(folder, "blocky_import_big")))
            with open(os.path.join(folder, "blocky_import_deep"), "w") as handle:
                handle.write(BASE + "x: " + "[" * 100000 + "]" * 100000 + "\n")
            self.assertIn("error", imported(folder, os.path.join(folder, "blocky_import_deep")))
            # a hard link names a file the web interface did not write; a FIFO would block the open
            os.link(outside, os.path.join(folder, "blocky_import_hard"))
            self.assertIn("error", imported(folder, os.path.join(folder, "blocky_import_hard")))
            os.mkfifo(os.path.join(folder, "blocky_import_fifo"))
            self.assertIn("error", imported(folder, os.path.join(folder, "blocky_import_fifo")))
            self.assertNotIn("error", run(""))

    def test_yaml_builds_no_objects_and_expands_no_aliases(self):
        marker = os.path.join(tempfile.gettempdir(), f"blocky_import_ran{os.getpid()}")
        result = run(f"x: !!python/object/apply:os.system ['touch {marker}']\n")
        self.assertIn("error", result)
        self.assertFalse(os.path.exists(marker))
        # a few aliases can repeat a block of entries without end
        bomb = "a0: &a0 [x, x, x, x, x, x, x, x, x]\n" + "".join(
            f"a{i}: &a{i} [{', '.join([f'*a{i - 1}'] * 9)}]\n" for i in range(1, 10))
        result = run(bomb + "blocking:\n  denylists:\n    ads: *a9\n  clientGroupsBlock:\n    default: *a9\n")
        self.assertIn("aliases are not imported", result["error"])
        self.assertIn("error", run("blocking:\n  denylists:\n    ads: &b [ads.lan]\n    kids: *b\n"))
        self.assertIn("error", run("caching: &c\n  minTime: 5m\nprefetching: *c\n"))

    def test_values_are_copied_as_written(self):
        result = run("upstreams:\n  timeout: 5\n  init:\n    strategy: fast\n  groups:\n    default: [1.1.1.1]\n"
                     "caching:\n  minTime: 1.5s\n  prefetching: true\n"
                     "redis:\n  address: r:6379\n  password: 0000\n  required: yes\n"
                     "ports:\n  dns: [53, 127.0.0.1:5353]\n"
                     "customDNS:\n  zone: |\n    nas.lan. 60 IN A 10.0.0.1\n")
        general, redis = result["scalars"]["general"], result["scalars"]["redis"]
        self.assertEqual((general["timeout"], general["initStrategy"], general["cacheMinTime"]), ("5", "fast", "1.5s"),
                         "a duration as Blocky reads it is for the settings to take or refuse")
        self.assertEqual((general["prefetching"], redis["required"]), ("1", "1"))
        self.assertEqual((redis["address"], redis["password"]), ("r:6379", "0000"))
        self.assertEqual(general["dnsPort"], "53,127.0.0.1:5353")
        self.assertEqual(general["customZone"], "nas.lan. 60 IN A 10.0.0.1")
        self.assertEqual(result["labels"]["scalars"]["general.cacheMinTime"], "caching.minTime")

    def test_rows(self):
        result = run("blocking:\n  denylists:\n    ads:\n      - https://example.com/ads.txt\n"
                     "      - /usr/local/etc/blocky/lists/mine.txt\n      - |\n        ads.example\n        # note\n\n"
                     "        /^ad[sx]\\./\n  clientGroupsBlock:\n    default: [ads, kids]\n"
                     "  schedules:\n    evenings:\n      weekdays: [mon, tue]\n      start: '18:00'\n      end: '22:00'\n"
                     "  listSchedules:\n    ads: [evenings]\n"
                     "customDNS:\n  mapping:\n    nas.lan: 10.0.0.1,10.0.0.2\n  rewrite:\n    fritz.box: lan\n"
                     "conditional:\n  mapping:\n    lan: 10.0.0.1\n"
                     "clientLookup:\n  clients:\n    printer: [10.0.0.9]\n"
                     "bootstrapDns:\n  - tcp-tls:1.1.1.1\n  - upstream: https://dns.google/dns-query\n    ips: [8.8.8.8, 8.8.4.4]\n"
                     "  - resolvFile: /usr/local/etc/blocky/lists/resolv.conf\n")
        arrays = result["arrays"]
        self.assertEqual([row["server"] for row in arrays["upstreams"]], ["1.1.1.1"])
        self.assertEqual([row["source"] for row in arrays["denylists"]],
                         ["https://example.com/ads.txt", "/usr/local/etc/blocky/lists/mine.txt", "ads.example", "/^ad[sx]\\./"],
                         "text with a line break is one entry per line, as Blocky reads it")
        self.assertEqual([(row["client"], row["groups"]) for row in arrays["clientgroups"]], [("default", "ads,kids")])
        self.assertEqual([(row["name"], row["weekdays"], row["start"], row["end"], row["groups"]) for row in arrays["schedules"]],
                         [("evenings", "mon,tue", "18:00", "22:00", "ads")])
        self.assertEqual([(row["domain"], row["ip"]) for row in arrays["customdns"]], [("nas.lan", "10.0.0.1,10.0.0.2")])
        self.assertEqual([(row["fromDomain"], row["toDomain"]) for row in arrays["customdnsrewrite"]], [("fritz.box", "lan")])
        self.assertEqual([(row["domain"], row["resolver"]) for row in arrays["conditional"]], [("lan", "10.0.0.1")])
        self.assertEqual([(row["name"], row["ips"]) for row in arrays["clientlookupclients"]], [("printer", "10.0.0.9")])
        self.assertEqual([(row["type"], row["content"], row.get("ips", "")) for row in arrays["bootstrap"]],
                         [("resolver", "tcp-tls:1.1.1.1", ""), ("resolver", "https://dns.google/dns-query", "8.8.8.8,8.8.4.4"),
                          ("resolvfile", "/usr/local/etc/blocky/lists/resolv.conf", "")])
        self.assertTrue(all(row["enabled"] == "1" for rows in arrays.values() for row in rows))
        self.assertEqual(result["labels"]["arrays"]["denylists"][0], "blocking.denylists.ads: https://example.com/ads.txt")

    def test_a_one_line_source_blocky_reads_as_a_file(self):
        result = run("blocking:\n  denylists:\n    ads: [lists/ads.txt, /etc/blocky/ads.txt]\n"
                     "hostsFile:\n  sources: [hosts.local, /etc/hosts]\n")
        # a relative path would be an inline entry to the settings; a full one is theirs to take or refuse
        self.assertEqual([row["source"] for row in result["arrays"]["denylists"]], ["/etc/blocky/ads.txt"])
        self.assertEqual(result["scalars"]["hostsFile"]["sources"], "/etc/hosts")
        self.assertTrue(warned(result, "blocking.denylists.ads: blocky reads lists/ads.txt as a file"))
        self.assertTrue(warned(result, "hostsFile.sources: blocky reads hosts.local as a file"))
        # a line of inline text that the settings would download or read as a file
        result = run("blocking:\n  denylists:\n    ads:\n      - |\n        ads.example\n        https://example.com/o.txt\n"
                     "        /etc/x.txt\n")
        self.assertEqual([row["source"] for row in result["arrays"]["denylists"]], ["ads.example"])
        self.assertTrue(warned(result, "blocking.denylists.ads: https://example.com/o.txt is a line of inline text to blocky"))
        self.assertTrue(warned(result, "blocking.denylists.ads: /etc/x.txt is a line of inline text to blocky"))
        # one entry of inline text still ends in a line break, as the template writes it
        result = run("blocking:\n  denylists:\n    ads:\n      - |\n        ads.example\n"
                     "hostsFile:\n  sources:\n    - |\n      10.0.0.1 nas.lan\n")
        self.assertEqual([row["source"] for row in result["arrays"]["denylists"]], ["ads.example"])
        self.assertEqual(result["scalars"]["hostsFile"]["sources"], "10.0.0.1 nas.lan")

    def test_keys_the_settings_have_no_field_for(self):
        result = run("blocking:\n  blackLists:\n    ads: [https://example.com/ads.txt]\n  blockTTL: 1m\n"
                     "certFile: /etc/blocky/cert.pem\nlog:\n  level: warn\n  target: /var/log/blocky.log\nfoo:\n  bar: 1\n")
        self.assertEqual(sorted(result["skipped"]), ["blocking.blackLists", "certFile", "foo", "log.target"])
        self.assertEqual(result["scalars"]["general"]["logLevel"], "warn")


if __name__ == "__main__":
    unittest.main()
