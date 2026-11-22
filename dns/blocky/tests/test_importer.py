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

    def test_dnssec_limits_of_zero_are_the_defaults(self):
        result = run("dnssec:\n  maxNSEC3Iterations: 0\n  maxUpstreamQueries: 0\n  maxChainDepth: 5\n")
        self.assertNotIn("maxNSEC3Iterations", result["scalars"]["dnssec"])
        self.assertNotIn("maxUpstreamQueries", result["scalars"]["dnssec"])
        self.assertEqual(result["scalars"]["dnssec"]["maxChainDepth"], "5")
        self.assertTrue(warned(result, "0 means blocky's default"))

    def test_no_query_log_type_is_the_console(self):
        for text in ("", "queryLog:\n", "queryLog:\n  type:\n"):
            result = run(text)
            self.assertEqual(result["scalars"]["queryLog"]["type"], "console", text)
            self.assertTrue(warned(result, "queryLog.type: not set, which blocky reads as Console"), text)
        self.assertEqual(run("queryLog:\n  type: none\n")["scalars"]["queryLog"]["type"], "none")
        # a true/false key left empty is off to blocky, and says so
        result = run("customDNS:\nqueryLog:\n  type: console\n")
        self.assertEqual(result["scalars"]["general"]["filterUnmappedTypes"], "0")
        self.assertTrue(warned(result, "customDNS.filterUnmappedTypes: empty, which blocky reads as off; imported as off."))

    def test_text_keeps_its_spelling(self):
        # blocky's yaml.v2 reads a string field as written; YAML 1.1 would make numbers of these
        result = run("redis:\n  address: r:6379\n  username: 007\n  password: 0000\n  sentinelPassword: 1.10\n"
                     "blocking:\n  denylists:\n    ads: [https://example.com/ads.txt]\n  clientGroupsBlock:\n    on: [ads]\n"
                     "queryLog:\n  type: console\n")
        self.assertEqual([result["scalars"]["redis"][k] for k in ("username", "password", "sentinelPassword")],
                         ["007", "0000", "1.10"])
        self.assertEqual(result["arrays"]["clientgroups"][0]["client"], "on")
        self.assertEqual(result["warnings"], [])
        self.assertEqual(run("ports:\n  dns: 53\nprometheus:\n  enable: yes\n")["scalars"]["general"]["prometheus"], "1")

    def test_profiler_switch(self):
        result = run("pprof:\n  enable: false\nqueryLog:\n  type: console\n")
        self.assertEqual(result["scalars"]["general"]["pprof"], "0")
        self.assertEqual(result["warnings"], [])

    def test_client_label_switch(self):
        result = run("prometheus:\n  enable: true\n  enableClientLabel: false\nqueryLog:\n  type: console\n")
        self.assertEqual(result["scalars"]["general"]["prometheusClientLabel"], "0")
        self.assertEqual(result["warnings"], [])

    def test_ignored_clients(self):
        result = run("queryLog:\n  type: console\n  ignore:\n    clients:\n      - 192.168.178.1\n"
                     "      - 192.168.178.64/28\n      - \" *-ap \"\n")
        self.assertEqual(result["scalars"]["queryLog"]["ignoreClients"], "192.168.178.1,192.168.178.64/28,*-ap")
        self.assertEqual(result["warnings"], [])

    def test_values_blocky_takes_fit_the_fields(self):
        result = run("blocking:\n  blockTTL: 0\n  schedules:\n    work:\n      weekdays: [Mon, Tue]\n      start: 09:00\n"
                     "      end: 17:00\n  listSchedules:\n    ads: [work]\n  denylists:\n    ads: [https://example.com/ads.txt]\n"
                     "upstreams:\n  timeout: 1.5s\nlog:\n  level: WARNING\nminTlsServeVersion: 1.1\n"
                     "caching:\n  minTime: 2.25h\n  maxTime: 0\n  cacheTimeNegative: .5s\n")
        general = result["scalars"]["general"]
        self.assertEqual((general["blockTTL"], general["timeout"], general["cacheMinTime"], general["cacheMaxTime"],
                          general["cacheTimeNegative"]),
                         ("0m", "1s500ms", "2h15m", "0", "500ms"), "a bare 0 stays where the field takes it")
        self.assertEqual(result["arrays"]["schedules"][0]["weekdays"], "mon,tue")
        self.assertEqual((general["logLevel"], general["minTlsServeVersion"]), ("warn", "1.2"))
        self.assertTrue(warned(result, "TLS 1.2"))

    def test_line_breaks_and_control_characters_are_left_out(self):
        # the fields refuse them, which would fail the whole import
        result = run('redis:\n  address: "r:6379\\r"\n  password: "pa\\nss"\n  sentinelPassword: "a\\rb"\n'
                     'hostsFile:\n  sources:\n    - "\\u2003/etc/hosts"\n    - "/usr/local/etc/blocky/lists/a\\x01b"\n'
                     'blocking:\n  denylists:\n    ads: ["a\\x7fb.com\\nads.example.com\\n"]\n'
                     'queryLog:\n  type: mysql\n  target: "u:p@tcp(db)/b\\n"\n')
        self.assertEqual(result["scalars"].get("redis", {}), {})
        self.assertEqual(result["scalars"]["hostsFile"]["sources"], "/etc/hosts")
        self.assertEqual([row["source"] for row in result["arrays"]["denylists"]], ["ads.example.com"])
        self.assertEqual(result["scalars"]["queryLog"]["type"], "none")
        for key in ("redis.address", "redis.password", "redis.sentinelPassword", "hostsFile.sources",
                    "blocking.denylists.ads", "queryLog.target"):
            self.assertTrue(warned(result, key), key)

    def test_a_group_without_lists(self):
        # blocky reads a one-line name as a file, and only warns about a group without lists, whose
        # blocking never applies; the settings refuse a reference to one, so the reference goes
        result = run("blocking:\n  denylists:\n    ads: [ads.example.com]\n    kids: [https://example.com/k.txt]\n"
                     "  clientGroupsBlock:\n    default: [ads, kids]\n    10.0.0.5: [ads]\n"
                     "  schedules:\n    work:\n      weekdays: [mon]\n  listSchedules:\n    ads: [work]\n"
                     "queryLog:\n  type: console\n")
        self.assertEqual([(r["client"], r["groups"]) for r in result["arrays"]["clientgroups"]], [("default", "kids")])
        self.assertNotIn("schedules", result["arrays"])
        self.assertTrue(warned(result, "blocking.clientGroupsBlock.default: group ads has no list"))
        self.assertTrue(warned(result, "blocking.clientGroupsBlock.10.0.0.5: none of its groups has a list; "
                                       "not imported, so the default groups apply"))
        self.assertTrue(warned(result, "blocking.listSchedules.ads: group ads has no list"))

    def test_a_duration_in_other_digits_is_refused_by_name(self):
        result = run("caching:\n  minTime: -²\n  maxTime: ²\nqueryLog:\n  type: console\n")
        self.assertNotIn("error", result)

    def test_rewrite_keys_blocky_reads_as_one(self):
        # blocky keeps either of two keys that differ in case, and never matches one with a trailing
        # dot, which the settings fold: the other is kept wherever it is
        result = run("customDNS:\n  rewrite:\n    fritz.box.: other.lan\n    Fritz.Box: fritz.lan\n    nas.lan: n.lan\n"
                     "conditional:\n  mapping:\n    lan: 192.168.1.1\n  rewrite:\n    LAN: home\n    ' lan': other\n")
        self.assertEqual([(r["fromDomain"], r["toDomain"]) for r in result["arrays"]["customdnsrewrite"]],
                         [("Fritz.Box", "fritz.lan"), ("nas.lan", "n.lan")])
        self.assertEqual([(r["fromDomain"], r["toDomain"]) for r in result["arrays"]["conditionalrewrite"]],
                         [("LAN", "home")])
        self.assertTrue(warned(result, "customDNS.rewrite.fritz.box.: the same domain as Fritz.Box"))
        self.assertTrue(warned(result, "conditional.rewrite. lan: the same domain as LAN"), "the settings trim it")

    def test_a_schedule_that_ends_where_it_starts(self):
        # blocky never applies it, which the settings refuse; dropping it or its group's lists
        # would change what the group's clients get
        result = run("blocking:\n  denylists:\n    ads: [https://example.com/ads.txt]\n    social: [https://example.com/s.txt]\n"
                     "  schedules:\n    never:\n      weekdays: [mon]\n      start: 00:00\n      end: '00:00'\n"
                     "    evenings:\n      weekdays: [mon, tue]\n      start: '18:00'\n      end: '22:00'\n"
                     "  listSchedules:\n    ads: [never]\n    social: [evenings, never]\n")
        rows = {row["name"]: row for row in result["arrays"]["schedules"]}
        # social is active when any of its schedules is, so it keeps only its evenings, as in blocky
        self.assertEqual((rows["evenings"]["groups"], rows["evenings"]["start"]), ("social", "18:00"))
        self.assertTrue(warned(result, "blocking.schedules.never: blocky never applies a schedule that ends where "
                                       "it starts, so social keeps only its other schedules."))
        # ads has no other, so it gets the schedule as all day: the settings have no window that never opens
        self.assertEqual((rows["never"]["groups"], rows["never"]["weekdays"], rows["never"]["start"], rows["never"]["end"]),
                         ("ads", "mon", "", ""))
        self.assertTrue(warned(result, "blocking.schedules.never: blocky never applies a schedule that ends where "
                                       "it starts; imported as all day for ads."))
        only_covered = run("blocking:\n  denylists:\n    social: [https://example.com/s.txt]\n  schedules:\n"
                           "    never:\n      weekdays: [mon]\n      start: '01:00'\n      end: '01:00'\n"
                           "    evenings:\n      weekdays: [mon]\n      start: '18:00'\n      end: '22:00'\n"
                           "  listSchedules:\n    social: [never, evenings]\n")
        self.assertEqual([row["name"] for row in only_covered["arrays"]["schedules"]], ["evenings"])

    def test_files_blocky_reads_are_in_the_plugin_directories(self):
        result = run("blocking:\n  denylists:\n    ads:\n      - /etc/master.passwd\n      - file:///etc/master.passwd\n"
                     "      - /usr/local/etc/blocky/lists/mine.txt\n      - /usr/local/etc/blocky/lists/../config.yml\n"
                     "hostsFile:\n  sources:\n    - /etc/hosts\n    - /etc/master.passwd\n"
                     "bootstrapDns:\n  - resolvFile: /etc/resolv.conf\n  - resolvFile: /usr/local/etc/blocky/lists/resolv.conf\n"
                     "redis:\n  address: /var/run/configd.socket\n  password: file:/etc/master.passwd\n"
                     "  sentinelPassword: file:/usr/local/etc/blocky/secrets/s\n  sentinelAddresses: [s1:26379, /tmp/x.sock]\n"
                     "queryLog:\n  type: dnstap\n  target: unix:/var/run/configd.socket\n")
        self.assertEqual([row["source"] for row in result["arrays"]["denylists"]], ["/usr/local/etc/blocky/lists/mine.txt"])
        self.assertEqual(result["scalars"]["hostsFile"]["sources"], "/etc/hosts")
        self.assertEqual([row["content"] for row in result["arrays"]["bootstrap"]], ["/usr/local/etc/blocky/lists/resolv.conf"])
        redis = result["scalars"]["redis"]
        self.assertNotIn("address", redis)
        self.assertNotIn("password", redis)
        self.assertEqual((redis["sentinelPassword"], redis["sentinelAddresses"]), ("file:/usr/local/etc/blocky/secrets/s", "s1:26379"))
        self.assertEqual(result["scalars"]["queryLog"]["type"], "none")
        for text in ("blocking.denylists.ads: /etc/master.passwd is a file outside /usr/local/etc/blocky/lists",
                     "hostsFile.sources: /etc/master.passwd is a file outside", "bootstrapDns.resolvFile: /etc/resolv.conf is outside",
                     "redis.address: only the Redis plugin socket", "redis.password: a file: value must name a file in",
                     "redis.sentinelAddresses: unix sockets", "queryLog.target: only tcp://host:port is taken for dnstap"):
            self.assertTrue(warned(result, text), text)
        database = run("queryLog:\n  type: mysql\n  target: file:/root/db\n")
        self.assertEqual(database["scalars"]["queryLog"]["type"], "none")
        self.assertNotIn("target", database["scalars"]["queryLog"])

    def test_sources_as_blocky_reads_them(self):
        # text with a line break is inline entries; one line is a download when it starts with http, else a file
        result = run("hostsFile:\n  sources:\n    - |\n      10.0.0.1\tprinter.lan\n      10.0.0.2  nas.lan\n"
                     "    - /etc/hosts\n    - hosts.local\n"
                     "blocking:\n  denylists:\n    ads:\n      - '0.0.0.0\tads.lan'\n      - lists/ads.txt\n"
                     "      - https://example.com/list.txt\n      - /usr/local/etc/blocky/lists/mine.txt\n"
                     "      - |\n        ads.example\n        https://example.com/other.txt\n        /^ad[sx]\\./\n")
        self.assertEqual(result["scalars"]["hostsFile"]["sources"], "10.0.0.1 printer.lan,10.0.0.2  nas.lan,/etc/hosts",
                         "a tab becomes a space, spaces stay as they are")
        self.assertEqual([row["source"] for row in result["arrays"]["denylists"]],
                         ["https://example.com/list.txt", "/usr/local/etc/blocky/lists/mine.txt", "ads.example", "/^ad[sx]\\./"])
        for text in ("blocky reads hosts.local as a file", "blocky reads 0.0.0.0\tads.lan as a file",
                     "blocky reads lists/ads.txt as a file", "https://example.com/other.txt is a line of inline text"):
            self.assertTrue(warned(result, text), text)

    def test_an_empty_key_is_what_blocky_reads(self):
        # blocky reads it as the zero value, not as its default: off for true/false settings
        result = run("pprof:\nspecialUseDomains:\n#  enable: false\ncustomDNS:\n  filterUnmappedTypes:\n"
                     "prometheus:\n  enable: true\n  enableClientLabel:\nqueryLog:\n  type: console\n  fields: []\n")
        self.assertEqual((result["scalars"]["general"]["pprof"], result["scalars"]["general"]["filterUnmappedTypes"],
                          result["scalars"]["general"]["prometheusClientLabel"]), ("0", "0", "0"))
        self.assertEqual(result["scalars"]["specialUseDomains"], {"enable": "0", "rfc6762": "0"})
        self.assertNotIn("fields", result["scalars"]["queryLog"])
        self.assertTrue(warned(result, "queryLog.fields: empty"))

    def test_negative_zero_is_zero(self):
        general = run("caching:\n  maxTime: -0s\n  minTime: -5m\nblocking:\n  loading:\n    downloads:\n"
                      "      readHeaderTimeout: -0s\n")["scalars"]["general"]
        self.assertEqual((general["cacheMaxTime"], general["cacheMinTime"], general["downloadReadHeaderTimeout"]),
                         ("0s", "-1", "0s"))
        # Go takes a sign on any duration
        general = run("blocking:\n  blockTTL: -0s\nupstreams:\n  timeout: +5s\n  groups:\n"
                      "    default: [1.1.1.1]\n")["scalars"]["general"]
        self.assertEqual((general["blockTTL"], general["timeout"]), ("0s", "5s"))

    def test_a_deprecated_key_wins_over_a_default(self):
        # blocky applies the deprecated value unless the new key holds something else than its default
        result = run("upstreamTimeout: 5s\nlogLevel: debug\nport: 5353\nstartVerifyUpstream: true\n"
                     "log:\n  level: info\nports:\n  dns: 53\nupstreams:\n  timeout: 2000ms\n  init:\n"
                     "    strategy: blocking\n  groups:\n    default: [1.1.1.1]\n")
        general = result["scalars"]["general"]
        self.assertEqual((general["timeout"], general["logLevel"], general["dnsPort"], general["initStrategy"]),
                         ("5s", "debug", "5353", "failOnError"))
        self.assertEqual(run("upstreamTimeout: 5s\nupstreams:\n  timeout: 3s\n  groups:\n    default: [1.1.1.1]\n")
                         ["scalars"]["general"]["timeout"], "3s")
        # a port list is the default too; an explicit {} is not, as blocky compares it with none
        self.assertEqual(run(BASE + "port: 5353\nports:\n  dns: [53]\n")["scalars"]["general"]["dnsPort"], "5353")
        result = run(BASE + "blocking:\n  blackLists:\n    ads: [ads.example]\n  denylists: {}\n")
        self.assertNotIn("denylists", result["arrays"])
        self.assertTrue(warned(result, "blocking.blackLists: deprecated and blocking.denylists is also set"))
        # blocky applies failStartOnListError first, and startStrategy then finds the strategy set
        result = run(BASE + "blocking:\n  startStrategy: fast\n  failStartOnListError: true\n")
        self.assertEqual(result["scalars"]["general"]["loadingStrategy"], "failOnError")

    def test_an_empty_key_is_left_to_the_default(self):
        result = run("ports:\n  dns: \"\"\nblocking:\n  blockTTL: \"\"\n  loading:\n    refreshPeriod: \"\"\n")
        self.assertNotIn("general", result["scalars"])

    def test_log_destination_is_left_to_the_plugin(self):
        result = run("log:\n  target: stderr\n  syslog:\n    tag: dns\n")
        self.assertIn("log.target: Blocky always logs to syslog on OPNsense.", result["skipped"])
        self.assertIn("log.syslog: Blocky always logs to syslog on OPNsense.", result["skipped"])
        self.assertFalse(warned(result, "not recognized"))

    def test_an_odd_date_is_text(self):
        self.assertNotIn("error", run("upstreams:\n  userAgent: 2026-13-45\n"))


if __name__ == "__main__":
    unittest.main()
