"""Channel URLs: files a service opens come only from the channel, and outside text is escaped."""

import http.server
import json
import os
import shutil
import sys
import tempfile
import threading
import time as time_module
import unittest

SCRIPTS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src", "opnsense", "scripts",
                       "OPNsense", "Notify")
sys.path.insert(0, os.path.join(SCRIPTS, "lib"))
sys.path.insert(0, SCRIPTS)

import chart  # noqa: E402
import common  # noqa: E402
import notify  # noqa: E402
import summary  # noqa: E402

notify.log = summary.log = lambda *args: None
CHANNEL = "11111111-2222-4333-8444-555555555555"  # a model UUID


class Case(unittest.TestCase):
    def setUp(self):
        self.keys = tempfile.mkdtemp()
        notify.KEY_DIR = os.path.join(self.keys, "keys")
        self.channel = {"uuid": CHANNEL, "url": "", "files": {}}
        notify.saved_channel = lambda uuid: self.channel

    def tearDown(self):
        shutil.rmtree(self.keys)

    def build(self, service, **fields):
        """Save the channel as the dialog would, and keep what was stored."""
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as handle:
            json.dump({"uuid": CHANNEL, "service": service, "fields": dict(changed="1", **fields)}, handle)
        try:
            result = notify.run_build(handle.name)
        finally:
            os.unlink(handle.name)
        if "url" in result:
            self.channel.update(url=result["url"], files=result["files"])
        return result


class FileArguments(Case):
    def test_only_where_the_service_opens_a_file(self):
        self.assertEqual(notify.file_args("discord"), {"template"})
        self.assertEqual(notify.file_args("guilded"), {"template"})  # a Discord subclass
        self.assertEqual(notify.file_args("mailtos"), {"pgppub", "pgpkey", "pgpprv"})
        self.assertEqual(notify.file_args("msg91"), set(), "a template ID, not a file")

    def test_local_files_are_refused(self):
        for url in ["discord://1/a?template=/etc/master.passwd", "discord://1/a?TEMPLATE=file:///etc/x",
                    "discord://1/a?template=%2Fetc%2Fx", "mailtos://u:p@e.com?pgpprv=/root/k"]:
            self.assertTrue(notify.local_file_args(url), url)
            self.assertIsNone(notify.check_url(url)[0], url)
        self.assertEqual(notify.local_file_args("msg91://a/s/p?template=abc123"), [])

    def test_only_public_files_are_fetched(self):
        self.assertEqual(notify.local_file_args("discord://1/a?template=https://example.com/t.json"), [])
        self.assertEqual(notify.local_file_args("mailtos://u:p@e.com?pgppub=https://keys.example/a.asc"), [])
        self.assertEqual(notify.local_file_args("mailtos://u:p@e.com?pgpprv=https://keys.example/a.asc"), ["pgpprv"])
        self.assertEqual(notify.local_file_args("discord://1/a?template=http://example.com/t.json"), ["template"],
                         "only fetched over https")


class StoredFiles(Case):
    WEBHOOK = {"webhook_id": "123", "webhook_token": "abc"}

    def test_paste_keep_replace_remove(self):
        result = self.build("discord", template='{"content": "old"}', **self.WEBHOOK)
        self.assertEqual(result["url"], "discord://123/abc?template=stored")
        self.assertEqual(result["files"], {"template": '{"content": "old"}\n'})
        self.assertEqual(self.build("discord", **self.WEBHOOK)["files"], {"template": '{"content": "old"}\n'})
        replaced = self.build("discord", template='{"content": "new"}', __clear_template="1", **self.WEBHOOK)
        self.assertEqual(replaced["files"], {"template": '{"content": "new"}\n'}, "typing wins over Remove")
        removed = self.build("discord", __clear_template="1", **self.WEBHOOK)
        self.assertEqual((removed["url"], removed["files"]), ("discord://123/abc", {}))

    def test_plain_http_is_refused(self):
        result = self.build("discord", template="http://example.com/t.json", **self.WEBHOOK)
        self.assertIn("https://", result["error"])

    def test_private_keys_are_pasted_not_fetched(self):
        result = self.build("mailtos", user="fw", password="pw", host="smtp.example.com", targets="a@example.com",
                            pgpprv="https://keys.example.com/private.asc")
        self.assertIn("a private key is not fetched", result["error"])
        result = self.build("mailtos", user="fw", password="pw", host="smtp.example.com", targets="a@example.com",
                            pgpprv="http://keys.example.com/private.asc")
        self.assertIn("a private key is not fetched", result["error"], "not asked for https first")

    def test_the_saved_url_reads_as_typed(self):
        result = self.build("mailtos", user="fw", password="pw", host="example.com", targets="admin@example.com")
        self.assertTrue(result["target"].endswith("/admin@example.com"), result["target"])

    def test_the_browser_never_gets_them(self):
        self.build("discord", template='{"content": "x"}', **self.WEBHOOK)
        described = notify.describe_url(self.channel["url"])
        self.assertNotIn("template", described["fields"])
        self.assertIn("template", described["saved"])

    def test_written_private_and_pruned(self):
        self.build("discord", template='{"content": "x"}', **self.WEBHOOK)
        path = os.path.join(notify.KEY_DIR, f"{CHANNEL}-template")
        url = notify.with_key_files(self.channel)
        self.assertIn(notify.urllib.parse.quote(path, safe=""), url)
        self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
        notify.prune_key_files([{"uuid": CHANNEL, "url": "discord://123/abc"}])
        self.assertFalse(os.path.exists(path))

    def test_an_encoded_marker_is_still_written(self):
        self.build("discord", template='{"content": "x"}', **self.WEBHOOK)
        self.channel["url"] = self.channel["url"].replace("template=stored", "templat%65=%73tored")
        self.assertIn(notify.urllib.parse.quote(notify.KEY_DIR, safe=""), notify.with_key_files(self.channel))
        notify.prune_key_files([self.channel])
        self.assertEqual(os.listdir(notify.KEY_DIR), [f"{CHANNEL}-template"], "kept while in use")

    def test_a_channel_id_is_not_a_path(self):
        self.build("discord", template='{"content": "x"}', **self.WEBHOOK)
        with self.assertRaises(ValueError):
            notify.with_key_files(dict(self.channel, uuid="../../etc/x"))
        with self.assertRaises(ValueError):
            summary.archive_report({}, "../x", "daily", 0)

    def test_a_request_that_is_not_an_object(self):
        for request in ([], {"fields": ["x"]}):
            with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as handle:
                json.dump(request, handle)
            try:
                self.assertIn("error", notify.run_build(handle.name))
                self.assertIn("error", notify.run_parse(handle.name))
            finally:
                os.unlink(handle.name)

    def test_import_asks_for_https(self):
        self.assertIn("Give an https:// address for template",
                      notify.check_url("discord://1/a?template=http://example.com/t.json")[1])

    def test_old_channels_with_http_are_told_to_use_https(self):
        ok, error = notify.deliver({"uuid": CHANNEL, "url": "discord://1/a?template=http://example.com/t.json"},
                                   "t", "b", "info")
        self.assertFalse(ok)
        self.assertIn("Give an https:// address for template", error)

    def test_pruning_without_key_files_skips_apprise(self):
        saved = notify.stored_file_args
        notify.stored_file_args = lambda url: self.fail("Apprise's services loaded for nothing")
        try:
            notify.prune_key_files([{"uuid": CHANNEL, "url": "discord://1/a"}])  # no key directory yet
            os.makedirs(notify.KEY_DIR)
            notify.prune_key_files([{"uuid": CHANNEL, "url": "discord://1/a"}])  # empty
        finally:
            notify.stored_file_args = saved

    def test_old_channels_with_a_path_do_not_send(self):
        ok, error = notify.deliver({"uuid": CHANNEL, "url": "discord://1/a?template=/etc/master.passwd"}, "t", "b", "info")
        self.assertFalse(ok)
        self.assertIn("paste its contents", error)


class Defaults(Case):
    """A default Apprise declares may hold for part of a service only, e.g. Email's STARTTLS."""
    FIELDS = {"user": "me@example.com", "password": "secret", "host": "example.com",
              "targets": "alerts@example.com", "smtp": "smtp.gmail.com"}

    def built(self, **fields):
        url, _, error = notify.from_service("mailtos", dict(self.FIELDS, **fields), "")
        self.assertEqual(error, "")
        return url, notify.check_url(url)[0]

    def test_a_chosen_mode_is_kept_where_it_is_not_the_default(self):
        url, plugin = self.built(schema="mailto", mode="starttls")
        self.assertIn("mode=starttls", url)
        self.assertEqual((plugin.secure_mode, plugin.port), ("starttls", 587))

    def test_a_real_default_is_still_left_out(self):
        url, plugin = self.built(schema="mailtos", mode="starttls")
        self.assertNotIn("mode=", url)
        self.assertEqual(plugin.secure_mode, "starttls")

    def test_the_dialog_shows_what_apprise_uses(self):
        url, _ = self.built(schema="mailto")
        self.assertEqual(notify.describe_url(url)["fields"]["mode"], "insecure")


class Escaping(unittest.TestCase):
    def test_outside_text_is_escaped_for_html_services(self):
        received = {}

        class Capture(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                received.update(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
                self.send_response(200)
                self.end_headers()

            def log_message(self, *args):
                pass

        server = http.server.HTTPServer(("127.0.0.1", 0), Capture)
        threading.Thread(target=server.handle_request, daemon=True).start()
        # a JSON target told to take HTML stands in for services that render it, e.g. Telegram
        url = f"json://127.0.0.1:{server.server_port}/?format=html"
        ok, _ = notify.deliver({"uuid": CHANNEL, "url": url}, "Failed login",
                               '<a href="https://evil.example">Unlock</a>', "warning")
        server.server_close()
        self.assertTrue(ok)
        self.assertNotIn("<a", received["message"])
        self.assertIn("&lt;a", received["message"])


class Collectors(Case):
    def ids(self, lines, mode="a"):
        with open(self.eve, mode) as handle:
            handle.writelines(line + "\n" for line in lines)

    def alert(self, n):
        return json.dumps({"event_type": "alert", "src_ip": "10.0.0.1", "dest_ip": "10.0.0.2",
                           "alert": {"signature": f"sig {n}", "severity": 1}}, separators=(",", ":"))

    def setUp(self):
        super().setUp()
        self.eve = os.path.join(self.keys, "eve.json")
        notify.IDS_LOG = self.eve
        self.ids(["start"], "w")
        self.state, _ = notify.check_ids({"general": {}}, None)

    def test_ids_reads_the_end_of_a_rotated_log(self):
        self.ids([self.alert(1)])
        os.rename(self.eve, self.eve + ".0")
        self.ids([self.alert(2)], "w")
        _, messages = notify.check_ids({"general": {}}, self.state)
        self.assertEqual([m["title"] for m in messages], ["sig 1", "sig 2"])

    def test_ids_reads_a_rotated_log_once_even_when_the_new_one_is_unreadable(self):
        self.ids([self.alert(1)])
        os.rename(self.eve, self.eve + ".0")
        self.ids([self.alert(2)], "w")
        os.chmod(self.eve, 0)
        try:
            state, messages = notify.check_ids({"general": {}}, self.state)
        finally:
            os.chmod(self.eve, 0o644)
        self.assertEqual([m["title"] for m in messages], ["sig 1"])
        _, messages = notify.check_ids({"general": {}}, state)
        self.assertEqual([m["title"] for m in messages], ["sig 2"])

    def test_ids_keeps_alerts_among_other_events_and_says_what_it_passed_over(self):
        flow = json.dumps({"event_type": "flow", "pad": "x" * 200})
        self.ids([flow] * 20000 + [self.alert(n) for n in range(notify.LOG_LINES + 3)] + [flow] * 20000)
        _, messages = notify.check_ids({"general": {}}, self.state)
        alerts = [m for m in messages if m["title"].startswith("sig ")]
        self.assertEqual(len(alerts), notify.LOG_LINES)
        self.assertEqual(alerts[-1]["title"], f"sig {notify.LOG_LINES + 2}")
        self.assertIn("3 IDS alerts before the latest", messages[0]["body"])

    def test_auth_reads_the_end_of_yesterday(self):
        config = {"general": {}}
        days = [os.path.join(self.keys, f"audit_{d}.log") for d in ("20260925", "20260926")]
        def write(path, mode, text):
            with open(path, mode) as handle:
                handle.write(text)
        write(days[0], "w", "start\n")
        notify.audit_log = lambda: days[0]
        state, _ = notify.check_auth(config, None)
        write(days[0], "a", "user admin: authentication failed\n")
        write(days[1], "w", "user root: authentication failed\n")
        notify.audit_log = lambda: days[1]
        _, messages = notify.check_auth(config, state)
        self.assertEqual([m["body"] for m in messages],
                         ["user admin: authentication failed", "user root: authentication failed"])

    def test_status_dropping_below_the_level_is_resolved(self):
        self.addCleanup(setattr, notify, "system_status", notify.system_status)
        item = {"statusCode": 0, "title": "Disk", "message": "low"}
        notify.system_status = lambda: {"disk": item}
        config = {"general": {"statusLevel": "warning"}}
        state, _ = notify.check_status(config, None)
        state["checked"] = 0
        notify.system_status = lambda: {"disk": dict(item, statusCode=1)}  # now a notice
        _, messages = notify.check_status(config, state)
        self.assertEqual([m["title"] for m in messages], ["Disk is resolved"])

    def test_ups_battery_fault_outranks_online(self):
        saved = notify.ups_status
        try:
            types = []
            for last, now in (("online", "online low battery"), ("online", "online lowbatt"),
                              ("online charging replace battery", "online replace battery")):
                notify.ups_status = lambda config, now=now: [("ups", now, "")]
                types.append(notify.check_ups({}, {"ups": last})[1][0]["type"])
        finally:
            notify.ups_status = saved
        self.assertEqual(types, ["failure", "failure", "warning"], "NUT and apcupsd; a lasting fault is not new")

    def test_a_ups_not_read_keeps_its_state(self):
        saved = notify.ups_status
        try:
            notify.ups_status = lambda config: []  # its daemon restarting
            state, _ = notify.check_ups({}, {"ups": "on battery"})
            notify.ups_status = lambda config: [("ups", "online", "")]
            _, messages = notify.check_ups({}, state)
        finally:
            notify.ups_status = saved
        self.assertEqual([m["title"] for m in messages], ["UPS ups is online"])

    def test_an_unreadable_status_code_is_not_resolved(self):
        self.addCleanup(setattr, notify, "system_status", notify.system_status)
        item = {"statusCode": -1, "title": "Crash", "message": "core dumped"}
        notify.system_status = lambda: {"crash": item}
        state, _ = notify.check_status({"general": {}}, None)
        state["checked"] = 0
        notify.system_status = lambda: {"crash": dict(item, statusCode=None)}
        _, messages = notify.check_status({"general": {}}, state)
        self.assertEqual(messages, [])

    def test_status_below_level_is_not_resolved(self):
        self.addCleanup(setattr, notify, "system_status", notify.system_status)
        item = {"statusCode": 0, "title": "Firmware", "message": "stale"}
        notify.system_status = lambda: {"firmware": item}
        state, _ = notify.check_status({"general": {"statusLevel": "warning"}}, None)
        state["checked"] = 0
        state, messages = notify.check_status({"general": {"statusLevel": "error"}}, state)
        self.assertEqual(messages, [])
        notify.system_status = lambda: {}
        state["checked"] = 0
        _, messages = notify.check_status({"general": {"statusLevel": "error"}}, state)
        self.assertEqual(messages, [])  # no longer tracked, so its recovery is not news either


class Summaries(unittest.TestCase):
    # core's `filter diag info interfaces`, as its pfstatistics.py reads pfctl -vvsInterfaces
    PF_INTERFACES = {"interfaces": {
        "all": {"cleared": "2026-09-24T10:00:00", "in4_pass_packets": 7, "in4_pass_bytes": 7},
        "vtnet0": {"cleared": "2026-09-24T10:00:00", "references": 12,
                   "in4_pass_packets": 1000, "in4_pass_bytes": 500000, "in4_block_packets": 20,
                   "in4_block_bytes": 1200, "out4_pass_packets": 900, "out4_pass_bytes": 90000,
                   "out4_block_packets": 0, "out4_block_bytes": 0, "in6_pass_packets": 10,
                   "in6_pass_bytes": 1000, "in6_block_packets": 5, "in6_block_bytes": 400}}}
    # core's `filter diag info rules`, as its pfstatistics.py reads pfctl -vvsrules
    PF_RULES = {"rules": {"nat rules": {}, "filter rules": {
        "@0 scrub on vtnet0 all fragment reassemble": {"evaluations": 100, "packets": 50, "bytes": 900, "states": 0},
        '@1 block drop in log inet all label "02f4bab031b57d1e30553ce08e0ec131"': {
            "evaluations": 1234, "packets": 40, "bytes": 2400, "states": 0, "inserted": "uid 0 pid 4242 ",
            "state_creations": 0},
        '@2 block drop in log inet6 all label "02f4bab031b57d1e30553ce08e0ec131"': {
            "evaluations": 1234, "packets": 2, "bytes": 120, "states": 0},
        '@3 pass in quick on lo0 all label "0f8a3d1e5b6c4d2e8f9a0b1c2d3e4f5a"': {
            "evaluations": 99, "packets": 999, "bytes": 9999, "states": 3}}}}

    PATCHED = ("sample_counters", "pf_states", "configctl_json", "boot_time", "addresses",
               "link_states", "carp_states", "read_firmware", "pf_interfaces",
               "pf_block_rules")

    def setUp(self):
        self.run = common.subprocess.run
        self.saved = {name: getattr(summary, name) for name in self.PATCHED}

    def tearDown(self):
        common.subprocess.run = self.run
        for name, value in self.saved.items():
            setattr(summary, name, value)

    def pf(self, rules):
        other = summary.configctl_json
        summary.configctl_json = lambda *args: rules if args == ("filter", "diag", "info", "rules") else other(*args)

    def test_interface_counters(self):
        summary.configctl_json = lambda *args: self.PF_INTERFACES if args == ("filter", "diag", "info",
                                                                             "interfaces") else None
        found, cleared = summary.pf_interfaces()
        self.assertEqual(found["vtnet0"]["in_pass"], [1010, 501000], "IPv4 and IPv6 together")
        self.assertEqual(found["vtnet0"]["in_block"], [25, 1600])
        self.assertEqual(cleared["vtnet0"], "2026-09-24T10:00:00")
        summary.configctl_json = lambda *args: None
        self.assertIsNone(summary.pf_interfaces(), "nothing read is not all zero")
        self.pf({})
        self.assertIsNone(summary.pf_block_rules())

    def test_an_odd_pf_value_costs_only_its_counter(self):
        odd = {"interfaces": {"vtnet0": {"in4_pass_packets": 5, "in4_pass_bytes": 50, "in4_block_packets": None,
                                         "in4_block_bytes": 1}}}
        summary.configctl_json = lambda *args: odd
        found, _ = summary.pf_interfaces()
        self.assertEqual(found, {"vtnet0": {"in_pass": [5, 50]}})

    def test_counters_sampled(self):
        summary.configctl_json = lambda *args: self.PF_INTERFACES
        self.pf(self.PF_RULES)
        sample, loads, cleared = self.saved["sample_counters"]({"vtnet0"}, True)
        self.assertEqual(sample["if vtnet0 in_pass bytes"], 501000)
        self.assertFalse([k for k in sample if " all " in k], "groups and unassigned interfaces left out")
        self.assertEqual(sample["rule 02f4bab031b57d1e30553ce08e0ec131"], 42)
        self.assertEqual(loads, {"02f4bab031b57d1e30553ce08e0ec131": "4242/2"})
        self.assertEqual(cleared, {"all": "2026-09-24T10:00:00", "vtnet0": "2026-09-24T10:00:00"})
        summary.pf_interfaces, summary.pf_block_rules = (lambda: None), (lambda: None)
        self.assertEqual(self.saved["sample_counters"]({"vtnet0"}, True), ({}, None, None),
                         "unreadable, not zero")
        self.assertEqual(self.saved["sample_counters"](set(), False), ({}, {}, {}), "not asked for")

    def test_current_status(self):
        now = 1_790_000_000
        summary.addresses = lambda: {"vtnet0": ["2001:db8::1", "192.0.2.1"]}
        summary.link_states = lambda names: {"vtnet0": "active", "vtnet1": "no carrier"}
        summary.carp_states = lambda: ["MASTER", "MASTER", "BACKUP"]
        gateways = {"WAN_GW": {"status_translated": "Online", "delay": "5.1 ms", "loss": "0.0 %"},
                    "WAN6_GW": {"status": "down"}}
        services = [{"name": "unbound", "description": "Unbound DNS", "status": "unbound is running as pid 7."},
                    {"name": "openvpn", "id": "1", "description": "OpenVPN client", "status": "openvpn is not running."},
                    {"name": "openvpn", "id": "2", "description": "OpenVPN client", "status": "openvpn is not running."},
                    {"name": "cron", "description": "Cron", "status": "cron is not running."},
                    {"name": "pf", "description": "Packet Filter", "nocheck": True, "status": "pf is running."}]
        answers = {("interface", "gateways", "status"): gateways, ("service", "list"): services}
        summary.configctl_json = lambda *args: answers.get(args)
        widget = common.configctl_json
        common.configctl_json = summary.configctl_json  # the Services widget rules read it there
        common.service_states.cache_clear()
        try:
            summary.read_firmware = lambda: {"connection": "ok", "upgrade_packages": [{"name": "a"}],
                                             "upgrade_major_version": "27.1", "last_check": "Mon Sep 28"}
            config = {"general": {"certDays": "14"}, "interfaces": {"vtnet0": "WAN", "vtnet1": "LAN"},
                      "uplinks": ["vtnet0"], "certificates": [
                          {"expires": now + 3 * 86400, "label": "Certificate", "description": "web"},
                          {"expires": now + 90 * 86400, "label": "Certificate", "description": "far"},
                          {"expires": now - 86400, "label": "Authority", "description": "old"}]}
            lines = summary.current_status(config, now)
            summary.read_firmware = lambda: {"connection": "error", "last_check": "Mon Sep 28"}
            failed = summary.current_status(config, now)
            summary.read_firmware = lambda: None
            missing = summary.current_status(config, now)
        finally:
            common.configctl_json = widget
            common.service_states.cache_clear()
        self.assertIn("WAN address: 192.0.2.1, 2001:db8::1", lines, "IPv4 first")
        self.assertIn("Gateway WAN_GW: Online, RTT 5.1 ms, loss 0.0 %", lines)
        self.assertIn("Gateway WAN6_GW: down", lines)
        self.assertIn("Links down: LAN no carrier", lines)
        self.assertIn("CARP: 1 BACKUP, 2 MASTER", lines)
        self.assertIn("Services: 1 of 4 running; stopped: Cron, OpenVPN client (2)", lines, "unchecked left out")
        self.assertTrue([line for line in lines if line.startswith("Firmware: 1 update(s) pending, 27.1 available")])
        self.assertEqual([line for line in lines if line.startswith(("Certificate", "Authority"))],
                         ["Authority old expired", "Certificate web expires in 3 day(s)"], "soonest first")
        self.assertIn("Firmware: The last update check failed (checked Mon Sep 28)", failed)
        self.assertIn("Firmware: No update check result", missing)

    def test_system_health(self):
        # as core's `system sysctl values` and `system diag disk` answer
        values = {"kern.boottime": "{ sec = 1790000000, usec = 0 } Mon Sep 21 00:00:00 2026",
                  "hw.physmem": "8000000000", "vm.stats.vm.v_page_count": "1000",
                  "vm.stats.vm.v_free_count": "200", "vm.stats.vm.v_inactive_count": "100",
                  "vm.stats.vm.v_cache_count": "0", "vm.stats.vm.v_laundry_count": "0",
                  "kstat.zfs.misc.arcstats.size": "2000000000"}
        disk = {"devices": [{"mountpoint": "/tmp", "used_pct": 1, "total_bytes": 1},
                            {"mountpoint": "/", "used_pct": 41, "total": "29.8G", "total_bytes": 32000000000}]}
        answers = {("system", "diag", "disk"): disk}
        summary.configctl_json = lambda *args: answers.get(args, values if args[:3] == ("system", "sysctl", "values")
                                                           else None)
        lines = summary.system_health()
        self.assertTrue(lines[0].startswith("Up "))
        self.assertEqual(lines[1:], ["Memory 45% used of 7,629 MB, ZFS cache 1,907 MB", "Disk 41% used of 29.8G"])
        del values["kstat.zfs.misc.arcstats.size"]
        self.assertEqual(summary.system_health()[1], "Memory 70% used of 7,629 MB", "UFS: no ZFS cache")
        summary.configctl_json = lambda *args: answers.get(args)
        self.assertEqual([line.split()[0] for line in summary.system_health()], ["Disk"], "sysctl unreadable")
        # up to 26.7, df's own JSON
        answers[("system", "diag", "disk")] = {"storage-system-information": {"filesystem": [
            {"name": "devfs", "type": "devfs  ", "blocks": "1.0K", "used-percent": 0, "mounted-on": "/dev"},
            {"name": "zroot/ROOT/default", "type": "zfs    ", "blocks": "10G", "used": "1.3G", "available": "9.2G",
             "used-percent": 12, "mounted-on": "/"}]}}
        self.assertEqual(summary.system_health(), ["Disk 12% used of 10G"])

    def test_block_rules_only(self):
        self.pf(self.PF_RULES)
        self.assertEqual(summary.pf_block_rules(), ({"02f4bab031b57d1e30553ce08e0ec131": 42},
                                                   {"02f4bab031b57d1e30553ce08e0ec131": "4242/2"}))

    def test_reset_counters_count_in_full(self):
        self.assertEqual(summary.counter_growth(None, {"a": 5}), {}, "first sample is the baseline")
        self.assertEqual(summary.counter_growth({"a": 5, "b": 9}, {"a": 8, "b": 3, "c": 4}),
                         {"a": 3, "b": 3}, "a counter not sampled before is a baseline")
        self.assertEqual(summary.counter_growth({}, {"rule x": 7}), {"rule x": 7}, "a rule that started matching")
        self.assertEqual(summary.counter_growth({}, {"rule x": 7}, rules=False), {}, "rules not sampled before")

    def test_rule_reload_resets_rule_counters(self):
        previous, current = {"rule x": 10000, "if a in_block packets": 50}, {"rule x": 12000, "if a in_block packets": 60}
        self.assertEqual(summary.counter_growth(previous, current, reset={"rule x"}),
                         {"rule x": 12000, "if a in_block packets": 10}, "interface counters survive a reload")
        summary.sample_counters = lambda devices, rules: (dict(current), {"x": "2"}, {})
        summary.pf_states = lambda: None
        channel = {"uuid": CHANNEL, "events": [], "summary": "daily", "summarySections": ["firewall"]}
        config = {"general": {}, "interfaces": {"a": "WAN"}}
        now = summary.last_boundary(int(notify.time.time()), "daily", 7, 1) - 60
        previous_state = {"counters": previous, "loads": {"x": "1"}, "rules": True,
                          "channels": {CHANNEL: {"since": now - 30, "schedule": "daily", "totals": {}, "peaks": {}}}}
        state, _ = summary.update_summaries(config, [channel], previous_state, [], now)
        self.assertEqual(state["channels"][CHANNEL]["totals"]["rule x"], 12000, "loaded by another pfctl")
        summary.sample_counters = lambda devices, rules: (dict(current), {"x": "1"}, {})
        state, _ = summary.update_summaries(config, [channel], previous_state, [], now)
        self.assertEqual(state["channels"][CHANNEL]["totals"]["rule x"], 2000, "the same load does not reset")
        summary.sample_counters = lambda devices, rules: (dict(current), {"x": "2"}, {})
        state, _ = summary.update_summaries(dict(config, keepCounters=True), [channel], previous_state, [], now)
        self.assertEqual(state["channels"][CHANNEL]["totals"]["rule x"], 2000, "kept counters only grow")

    def test_failed_and_cleared_readings(self):
        self.assertEqual(summary.counter_growth({"rule x": 1000005}, {"rule x": 800010}, shrunk={"rule x"}), {},
                         "a label that lost rules keeps the rest's counts")
        self.assertEqual(summary.counter_growth({"rule x": 1000005}, {"rule x": 8000}), {"rule x": 8000},
                         "an edited rule starts again")
        summary.pf_states = lambda: None
        channel = {"uuid": CHANNEL, "events": [], "summary": "daily", "summarySections": ["firewall"]}
        config = {"general": {"summaryHour": "24"}, "interfaces": {"a": "WAN"}}
        now = summary.last_boundary(int(notify.time.time()), "daily", 7, 1) - 1000
        state = {"counters": {"rule x": 5000000, "if a in_block packets": 50}, "loads": {"x": "1"},
                 "cleared": {"a": "T1"}, "rules": True,
                 "channels": {CHANNEL: {"since": now - 30, "schedule": "daily", "totals": {}, "peaks": {}}}}
        summary.sample_counters = lambda devices, rules: ({"if a in_block packets": 55}, None, {"a": "T1"})
        state, _ = summary.update_summaries(config, [channel], state, [], now)
        self.assertEqual(state["channels"][CHANNEL]["totals"], {"if a in_block packets": 5}, "rules not read")
        summary.sample_counters = lambda devices, rules: ({"rule x": 5000010, "if a in_block packets": 60},
                                                         {"x": "1"}, {"a": "T2"})
        state, _ = summary.update_summaries(config, [channel], state, [], now + 60)
        self.assertEqual(state["channels"][CHANNEL]["totals"], {"if a in_block packets": 5}, "read at most every 5 minutes")
        state, _ = summary.update_summaries(config, [channel], state, [], now + summary.SAMPLE_SECONDS)
        self.assertEqual(state["channels"][CHANNEL]["totals"], {"if a in_block packets": 65, "rule x": 10},
                         "a cleared interface starts from zero; the rule carried over grows by 10")

    def test_kept_counters_edit_or_removal(self):
        summary.pf_states = lambda: None
        summary.boot_time = lambda: 100
        channel = {"uuid": CHANNEL, "events": [], "summary": "weekly", "summarySections": ["firewall"]}
        now = summary.last_boundary(int(notify.time.time()), "weekly", 7, 1) + 60
        config = {"general": {}, "keepCounters": True, "interfaces": {}}
        for rules, expected in ((2, 8000), (1, 0)):
            state = {"counters": {"rule x": 10000}, "loads": {"x": "1/2"}, "rules": True, "boot": 100,
                     "channels": {CHANNEL: {"since": now - 30, "schedule": "weekly", "totals": {}, "peaks": {}}}}
            summary.sample_counters = lambda devices, r, n=rules: ({"rule x": 8000}, {"x": f"9/{n}"}, {})
            state, _ = summary.update_summaries(config, [channel], state, [], now)
            self.assertEqual(state["channels"][CHANNEL]["totals"].get("rule x", 0), expected,
                             "edited: its counter restarted" if rules == 2 else "a pf rule of the label removed")

    def test_kept_counters_reset_on_reboot(self):
        summary.pf_states = lambda: None
        summary.sample_counters = lambda devices, rules: ({"rule x": 3000}, {"x": "9"}, {})
        channel = {"uuid": CHANNEL, "events": [], "summary": "weekly", "summarySections": ["firewall"]}
        now = summary.last_boundary(int(notify.time.time()), "weekly", 7, 1) + 60
        state = {"counters": {"rule x": 5000000}, "loads": {"x": "1"}, "rules": True, "boot": 100,
                 "channels": {CHANNEL: {"since": now - 30, "schedule": "weekly", "totals": {}, "peaks": {}}}}
        summary.boot_time = lambda: 200
        state, _ = summary.update_summaries({"general": {}, "keepCounters": True, "interfaces": {}}, [channel],
                                           state, [], now)
        self.assertEqual(state["channels"][CHANNEL]["totals"], {"rule x": 3000})

    def test_new_period_keeps_the_closing_reading(self):
        summary.pf_states = lambda: (900, 1000)
        summary.sample_counters = lambda devices, rules: ({}, {}, {})
        channel = {"uuid": CHANNEL, "events": [], "summary": "daily", "summarySections": ["health"]}
        now = summary.last_boundary(int(notify.time.time()), "daily", 7, 1) + 60
        state = {"channels": {CHANNEL: {"since": now - 86400, "schedule": "daily", "totals": {}, "peaks": {}}}}
        state, due = summary.update_summaries({"general": {}, "interfaces": {}}, [channel], state, [], now)
        self.assertEqual(len(due), 1)
        self.assertEqual(state["channels"][CHANNEL]["peaks"]["states"], 900)

    def test_monthly_boundaries(self):
        def at(*args):
            return int(summary.datetime.datetime(*args).timestamp())

        def boundary(now, date):
            return summary.datetime.datetime.fromtimestamp(summary.last_boundary(now, "monthly", 7, 1, date))
        self.assertEqual(boundary(at(2026, 3, 15, 12), 31), summary.datetime.datetime(2026, 2, 28, 7))
        self.assertEqual(boundary(at(2026, 3, 31, 8), 31), summary.datetime.datetime(2026, 3, 31, 7))
        self.assertEqual(boundary(at(2026, 1, 10, 12), 15), summary.datetime.datetime(2025, 12, 15, 7))
        self.assertEqual(boundary(at(2028, 2, 29, 6), 31), summary.datetime.datetime(2028, 1, 31, 7))
        self.assertEqual(boundary(at(2028, 3, 1, 6), 31), summary.datetime.datetime(2028, 2, 29, 7))
        self.assertEqual(boundary(at(2026, 5, 1, 6), 30), summary.datetime.datetime(2026, 4, 30, 7))
        self.assertEqual(boundary(at(2026, 3, 1, 6), 30), summary.datetime.datetime(2026, 2, 28, 7),
                         "a day past a short month's end is its last day")

    def test_boundaries(self):
        now = int(summary.datetime.datetime(2026, 9, 26, 6, 30).timestamp())  # a Saturday
        self.assertEqual(summary.datetime.datetime.fromtimestamp(summary.last_boundary(now, "daily", 7, 1)),
                         summary.datetime.datetime(2026, 9, 25, 7, 0))
        self.assertEqual(summary.datetime.datetime.fromtimestamp(summary.last_boundary(now, "weekly", 7, 1)),
                         summary.datetime.datetime(2026, 9, 21, 7, 0))

    def test_period_is_due_once_after_its_hour(self):
        summary.sample_counters = lambda devices, rules: ({"if vtnet0 in_block packets": 10, "if vtnet0 in_pass bytes": 5}, {}, {})
        summary.pf_states = lambda: (100, 1000)
        channel = {"uuid": CHANNEL, "events": [], "summary": "daily", "summaryEvents": ["gateway"],
                   "summarySections": ["firewall", "health"]}
        config = {"general": {"summaryHour": "7"}, "interfaces": {"vtnet0": "WAN"}}
        start = int(summary.datetime.datetime(2026, 9, 26, 6, 0).timestamp())
        state, due = summary.update_summaries(config, [channel], None, [], start)
        self.assertEqual(due, [])
        summary.sample_counters = lambda devices, rules: ({"if vtnet0 in_block packets": 25, "if vtnet0 in_pass bytes": 9}, {}, {})
        state, due = summary.update_summaries(config, [channel], state, [], start + 1800)
        self.assertEqual(due, [])
        self.assertEqual(state["channels"][CHANNEL]["totals"], {"if vtnet0 in_block packets": 15},
                         "traffic is not among the channel's sections")
        found = summary.message("gateway", "failure", "Gateway WAN_GW is down", "")
        state, due = summary.update_summaries(config, [channel], state, [found], start + 3660)
        self.assertEqual(len(due), 1)
        self.assertEqual(due[0][1]["events"], {"gateway": 1}, "found in the check that ends the period")
        self.assertEqual(state["channels"][CHANNEL]["totals"], {}, "a new period starts")
        _, due = summary.update_summaries(config, [channel], state, [], start + 3720)
        self.assertEqual(due, [])

    def test_summary_events_are_not_sent_as_they_happen(self):
        channel = {"uuid": CHANNEL, "events": ["config"], "summary": "weekly", "summaryEvents": ["gateway"]}
        gateway = summary.message("gateway", "failure", "Gateway WAN_GW is down", "")
        self.assertEqual(summary.subscribed([channel]), {"config", "gateway"})
        self.assertFalse(notify.wants(channel, gateway))
        period = summary.add_events({}, channel, [gateway, summary.message("config", "info", "x", "")])
        self.assertEqual(period["events"], {"gateway": 1})

    def test_report(self):
        summary.configctl_json = lambda *args: [{"id": "02f4", "descr": "Default deny / state violation rule"}] \
            if args == ("filter", "list", "rule_ids") else None
        channel = {"uuid": CHANNEL, "summary": "weekly", "summaryEvents": ["gateway"],
                   "summarySections": ["firewall", "traffic"]}
        now = int(notify.time.time())
        period = {"since": now - 3600, "events": {"gateway": 1},
                  "recent": [{"title": "Gateway WAN_GW is down", "time": now - 60}], "totals": {
            "if vtnet0 in_block packets": 1500, "if vtnet0 in_block bytes": 90000,
            "if vtnet0 in_pass bytes": 2500000, "if vtnet0 out_pass bytes": 300000, "rule 02f4": 1500}}
        config = {"interfaces": {"vtnet0": "WAN"}, "eventLabels": {"gateway": "Gateway status"}}
        item = summary.build_summary(config, channel, period, now)
        self.assertEqual((item["event"], item["uuid"], item["title"]), ("summary", CHANNEL, "Weekly summary"))
        rows = {part["title"]: part["rows"] for part in item["report"]["sections"]}
        self.assertEqual(rows["Events in the period"], [["Gateway status", "1"]])
        self.assertIn("Latest 1 of 1", rows)
        self.assertEqual(rows["Firewall blocks"], [["WAN", "1,500", "0", "90.0 kB"]])
        self.assertEqual(rows["Block rules matched most"], [["Default deny / state violation rule", "1,500"]])
        self.assertEqual(rows["Traffic"], [["WAN", "2.5 MB", "300.0 kB"]])
        self.assertEqual(item["body"].splitlines()[1:], [
            "Events: 1 Gateway status", "Blocked: 1,500 packets",
            "Most blocks: Default deny / state violation rule (1,500)", "Traffic: WAN 2.5 MB in, 300.0 kB out"],
            "the short text for services that are not email")


class SummaryTiming(unittest.TestCase):
    def setUp(self):
        self.tz = os.environ.get("TZ")

    def tearDown(self):
        if self.tz is None:
            os.environ.pop("TZ", None)
        else:
            os.environ["TZ"] = self.tz
        notify.time.tzset()

    def test_the_repeated_hour_when_clocks_go_back_is_due_once(self):
        os.environ["TZ"] = "America/New_York"
        notify.time.tzset()
        first = 1793509500  # 2026-11-01 01:05 EDT; an hour later it is 01:05 again, EST
        boundary = summary.last_boundary(first, "daily", 1, 1)
        self.assertLessEqual(boundary, first)
        self.assertEqual(summary.last_boundary(first + 3600, "daily", 1, 1), boundary)

    def test_a_queued_summary_goes_only_while_the_channel_has_one(self):
        item = summary.message("summary", "info", "Daily summary", "")
        self.assertTrue(notify.wants({"events": [], "summary": "daily"}, item))
        self.assertFalse(notify.wants({"events": [], "summary": "none"}, item))

    def test_a_period_opened_now_starts_from_a_reading_taken_now(self):
        taken = []
        saved = summary.sample_growth, summary.pf_states
        summary.sample_growth = lambda *args: taken.append(1) or ({}, {"counters": {}})
        summary.pf_states = lambda: None
        try:
            now = 1790000000
            previous = {"counters": {}, "sampled": now - 10, "channels": {}}
            channel = {"uuid": CHANNEL, "summary": "daily", "summarySections": ["traffic"], "events": []}
            summary.update_summaries({"general": {}}, [channel], previous, [], now)
        finally:
            summary.sample_growth, summary.pf_states = saved
        self.assertEqual(taken, [1], "read now, although the last reading was only seconds ago")

    def test_each_graph_is_drawn_once_per_run(self):
        drawn, saved = [], summary.draw_graph
        summary.draw_graph = lambda spec, directory: drawn.append(spec["name"]) or f"/x/{spec['name']}"
        summary.GRAPHS.clear()
        try:
            spec = {"name": "cpu-system.png", "start": 1, "end": 2}
            self.assertEqual(summary.drawn_graph(spec), summary.drawn_graph(dict(spec)))
            summary.drawn_graph(dict(spec, end=3))
        finally:
            summary.draw_graph = saved
            summary.GRAPHS.clear()
        self.assertEqual(drawn, ["cpu-system.png", "cpu-system.png"], "once per period, not per channel")

    @staticmethod
    def health(rows, step=300):
        """Core's `health fetch` answer for {source: [values]} from 1727000100 on, one step apart."""
        count = len(next(iter(rows.values())))
        last = 1727000100 + (count - 1) * step
        return {"step": step, "lastupdate": last, "sets": [{
            "pdp_per_row": 1, "step_size": step, "recorded_time": (count - 1) * step,
            "ds": [{"key": name, "values": [[(1727000100 + i * step) * 1000, v] for i, v in enumerate(values)]}
                   for name, values in rows.items()]}]}

    FETCH = {"inblock": [10.0, None, 30.0], "outblock": [2.0, None, 4.0], "inblock6": [5.0, None, None],
             "outblock6": [None, None, 1.0]}

    def test_the_finest_average_that_reaches_back(self):
        fine = self.health({"user": [1.0, 2.0]}, step=60)["sets"][0]
        coarse = self.health({"user": [5.0] * 10}, step=60)["sets"][0]
        coarse.update(step_size=300, recorded_time=2700)
        data = {"lastupdate": 1727000160, "sets": [fine, coarse]}
        self.assertEqual(len(summary.health_rows(data, 1727000100, 1727000160)), 2, "the fine one reaches back")
        rows = summary.health_rows(data, 1726998000, 1727000160)
        self.assertEqual(rows[1][0] - rows[0][0], 300, "else the one that reaches furthest")

    def test_an_infinite_reading_is_a_gap(self):
        rows = summary.health_rows(self.health({"user": [1.0, None, float("-inf")]}), 1727000100, 1727000700)
        self.assertEqual([row["user"] for _, row in rows], [1.0, None, None])

    def test_fetch_keeps_gaps(self):
        rows = summary.health_rows(self.health(self.FETCH), 1727000100, 1727000700)
        self.assertEqual([stamp for stamp, _ in rows], [1727000100, 1727000400, 1727000700])
        self.assertEqual(rows[0][1], {"inblock": 10.0, "outblock": 2.0, "inblock6": 5.0, "outblock6": None})
        self.assertEqual(set(rows[1][1].values()), {None})

    def test_blocked_graph_counts_packets_both_ways(self):
        rrd, calls = tempfile.mkdtemp(), []
        saved = summary.configctl_json
        summary.configctl_json = lambda *args: calls.append(args) or self.health(self.FETCH)
        try:
            graph = summary.draw_graph({"kind": "blocks", "key": "wan", "name": "b.png", "title": "WAN blocked",
                                       "start": 1727000100, "end": 1727000700}, rrd)
            with open(graph["path"], "rb") as handle:
                image = handle.read()
        finally:
            summary.configctl_json = saved
            shutil.rmtree(rrd)
        self.assertEqual(calls[0], ("health", "fetch", "wan-packets.rrd"))
        self.assertEqual(image[:8], b"\x89PNG\r\n\x1a\n")
        self.assertEqual(chart.struct.unpack(">II", image[16:24]), chart.GRAPH_SIZE)
        self.assertEqual(graph["legend"], [("In", "#e15759", "peak 30 packets/s, average 22 packets/s", "area"),
                                           ("Out", "#76b7b2", "peak 5 packets/s, average 4 packets/s", "line")],
                         "IPv4 and IPv6 added")

    def test_stale_health_data_is_logged(self):
        rrd, logged = tempfile.mkdtemp(), []
        saved = summary.configctl_json, summary.log
        summary.configctl_json = lambda *args: self.health({"user": [None, None]}, step=60)
        summary.log = lambda priority, text: logged.append(text)
        try:
            graph = summary.draw_graph({"kind": "cpu", "key": "system", "name": "c.png", "title": "Processor",
                                        "start": 1727000100, "end": 1727000160}, rrd)
        finally:
            summary.configctl_json, summary.log = saved
            shutil.rmtree(rrd)
        self.assertIsNone(graph)
        self.assertIn("has no data for the period", logged[0], "files left from when health reporting was on")

    def test_graphs_per_setting(self):
        totals = {f"if igc{i} {kind} {unit}": 1000 - i for i in range(5)
                  for kind in ("in_pass", "in_block") for unit in ("bytes", "packets")}
        # busiest, but unassigned since, so it has no health data
        totals.update({f"if igc9 {kind} {unit}": 5000 for kind in ("in_pass", "in_block") for unit in ("bytes", "packets")})
        config = {"interfaces": {f"igc{i}": f"NET{i}" for i in range(5)},
                  "ifnames": {f"igc{i}": f"opt{i}" for i in range(5)}}
        channel = {"uuid": CHANNEL, "summary": "daily", "summarySections": ["firewall", "traffic", "health"],
                   "summaryEvents": []}
        period = {"since": 0, "schedule": "daily", "totals": totals, "peaks": {}}
        saved = summary.system_health, summary.configctl_json
        summary.system_health, summary.configctl_json = (lambda: []), (lambda *a: None)
        try:
            drawn, colored = {}, {}
            for choice in ("none", "top1", "top3", "all"):
                report = summary.build_summary(dict(config, general={"summaryGraphs": choice}), channel, period, 100)
                drawn[choice] = [[g["name"] for g in p["graphs"]] for p in report["report"]["sections"]]
                colored[choice] = [[g.get("color") for g in p["graphs"]] for p in report["report"]["sections"]]
        finally:
            summary.system_health, summary.configctl_json = saved
        self.assertEqual(drawn["none"], [[], [], []])
        self.assertEqual(drawn["top1"], [["blocks-opt0.png"], ["traffic-opt0.png"], ["cpu-system.png", "states-system.png"]],
                         "one without health data is passed over, not counted")
        self.assertEqual([len(p) for p in drawn["top3"]], [3, 3, 2], "busiest first, blocks as well as traffic")
        self.assertEqual([len(p) for p in drawn["all"]], [5, 5, 2])
        self.assertEqual(colored["top3"][1], list(chart.PIE_COLORS[1:4]),
                         "each as its donut slice; the busiest, without health data, keeps its color")
        self.assertEqual(colored["top3"][2], [None, None], "system graphs keep their own")

    def test_no_graphs_without_health_reporting(self):
        channel = {"uuid": CHANNEL, "summary": "daily", "summarySections": ["health"], "summaryEvents": []}
        period = {"since": 0, "schedule": "daily", "peaks": {}}
        saved = summary.system_health
        summary.system_health = lambda: []
        try:
            off = summary.build_summary({"healthReporting": False}, channel, period, 100)["report"]
            on = summary.build_summary({"healthReporting": True}, channel, period, 100)["report"]
        finally:
            summary.system_health = saved
        self.assertEqual([p["graphs"] for p in off["sections"]], [[]])
        self.assertIn("health reporting is off", summary.summary_html(off, {}))
        self.assertEqual((on["note"], len(on["sections"][0]["graphs"])), ("", 2))
        saved = summary.system_health
        summary.system_health = lambda: []
        try:
            none = summary.build_summary({"healthReporting": False, "general": {"summaryGraphs": "none"}},
                                         channel, period, 100)["report"]
        finally:
            summary.system_health = saved
        self.assertEqual(none["note"], "", "no graphs were wanted")
        summary.system_health = lambda: []
        try:
            every = summary.build_summary({"healthReporting": False, "general": {"summaryGraphs": "all"}},
                                          channel, period, 100)["report"]
        finally:
            summary.system_health = saved
        self.assertIn("health reporting is off", every["note"], "all is no limit, not none")

    def test_an_interface_graph_takes_its_slice_color(self):
        rrd = tempfile.mkdtemp()
        saved = summary.configctl_json
        summary.configctl_json = lambda *args: self.health({"inpass": [1.0, 3.0], "outpass": [2.0, 4.0]})
        try:
            graph = summary.draw_graph({"kind": "traffic", "key": "wan", "name": "t.png", "title": "WAN traffic",
                                        "start": 1727000100, "end": 1727000400, "color": "#f28e2b"}, rrd)
        finally:
            summary.configctl_json = saved
            shutil.rmtree(rrd)
        self.assertEqual([(color, look) for _, color, _, look in graph["legend"]],
                         [("#f28e2b", "area"), ("#f28e2b", "line")], "In the area, Out the line")
        caption = summary.graph_caption_html("WAN traffic", graph)
        self.assertIn(f'<span style="color:#f28e2b;opacity:{chart.AREA_SHADE}">&#9632;</span>&nbsp;In', caption,
                      "its square shaded as the area")

    def test_brief_status(self):
        lines = ["WAN address: 203.0.113.7, 2001:db8::7, fd00::7", "Gateway WAN: Online, RTT 1.1 ms, loss 0.0 %",
                 "Gateway WAN6: Online", "Gateway VPN: Latency, Packetloss, RTT 900 ms, loss 30.0 %",
                 "6 of 6 interface links up"] + [f"Certificate c{i} expires in {i} day(s)" for i in range(5)]
        self.assertEqual(summary.brief_status(lines), [
            "WAN address: 203.0.113.7 (+2)", "Gateways: 2 online; VPN Latency, Packetloss", "6 of 6 interface links up",
            "Certificate c0 expires in 0 day(s)", "Certificate c1 expires in 1 day(s)", "Certificate c2 expires in 2 day(s)",
            "and 2 more certificates"])
        self.assertIn("Gateways: WAN down", summary.brief_status(["Gateway WAN: down"]), "none online")

    def test_rates(self):
        self.assertEqual(summary.rate(950, "bits"), "950 bit/s")
        self.assertEqual(summary.rate(212_400_000, "bits"), "212.4 Mbit/s")
        self.assertEqual(summary.rate(3_120, "states"), "3,120")
        self.assertEqual(summary.rate(12.4, "percent"), "12%")

    def test_day_marks(self):
        first = int(summary.datetime.datetime(2026, 9, 1, 12).timestamp())
        self.assertEqual(len(chart.day_marks(first, first + 3 * 86400)), 3)
        self.assertEqual(len(chart.day_marks(first, first + 30 * 86400)), 4, "Mondays only over a month")


class Model(unittest.TestCase):
    def test_summary_offers_the_same_events(self):
        import xml.etree.ElementTree as ET
        model = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src", "opnsense", "mvc", "app",
                             "models", "OPNsense", "Notify", "Notify.xml")
        root = ET.parse(model).getroot()
        options = [[(o.tag, o.text) for o in root.find(f".//{name}/OptionValues")]
                   for name in ("events", "summaryEvents")]
        self.assertEqual(options[0], options[1], "an event added to one list belongs in the other")


class SummaryEmail(unittest.TestCase):
    REPORT = {"title": "Daily summary", "span": "a to b", "sections": [
        {"title": "Latest 1 of 1", "head": ["Time", "Event"], "rows": [["12:00", "Failed login for <b>x</b>"]],
         "lines": ["12:00 Failed login for <b>x</b>"],
         "graphs": [{"kind": "cpu", "key": "system", "title": "Processor", "name": "cpu-system.png", "start": 0, "end": 1}]}]}

    def setUp(self):
        import apprise
        self.apprise = apprise
        self.original = apprise.Apprise.notify
        self.draw = summary.draw_graph
        summary.GRAPHS.clear()
        self.calls = []
        apprise.Apprise.notify = lambda this, **kw: self.calls.append(kw) or True

    def tearDown(self):
        self.apprise.Apprise.notify = self.original
        summary.draw_graph = self.draw

    def test_a_late_summary_says_so(self):
        body = summary.summary_html(dict(self.REPORT, delayed="(Delayed: this happened at 07:00.)"), {})
        self.assertIn("<em>(Delayed: this happened at 07:00.)</em>", body)

    def test_escaped_with_graphs_in_their_section(self):
        body = summary.summary_html(self.REPORT, {"cpu-system.png": {"path": "/tmp/x", "legend": [("", "#4e79a7", "<peak>", "area")]}})
        self.assertIn("Failed login for &lt;b&gt;x&lt;/b&gt;", body)
        self.assertIn('<img src="cid:cpu-system.png"', body)
        self.assertIn("&#9632;</span>&nbsp;&lt;peak&gt;</small>", body)
        legend = {"path": "/tmp/x", "legend": [("In", "#4e79a7", "peak 2 bit/s, average 1 bit/s", "area"),
                                                               ("Out", "#e15759", "peak <1>, average 0", "line")]}
        body = summary.summary_html(self.REPORT, {"cpu-system.png": legend})
        self.assertIn(f'<span style="color:#4e79a7;opacity:{chart.AREA_SHADE}">&#9632;</span>&nbsp;In peak 2 bit/s', body)
        self.assertIn('<span style="color:#e15759">&#9473;</span>&nbsp;Out peak &lt;1&gt;', body,
                      "a line's swatch is a bar, kept with its label")
        self.assertNotIn("cid:", summary.summary_html(self.REPORT, {}), "a graph not drawn is left out")

    def test_html_only_for_email(self):
        summary.draw_graph = lambda spec, directory: None
        notify.deliver({"uuid": CHANNEL, "url": "mailto://127.0.0.1?from=a@example.com&to=b@example.com"},
                       "t", "text", "info", self.REPORT)
        notify.deliver({"uuid": CHANNEL, "url": "tgram://123456789:abcdefg_hijklmnop/1"}, "t", "text", "info", self.REPORT)
        notify.deliver({"uuid": CHANNEL, "url": "mailto://127.0.0.1?from=a@example.com&to=b@example.com&format=text"},
                       "t", "text", "info", self.REPORT)
        self.assertEqual([c["body_format"] for c in self.calls],
                         [self.apprise.NotifyFormat.HTML, self.apprise.NotifyFormat.TEXT, self.apprise.NotifyFormat.TEXT])
        self.assertEqual(self.calls[1]["body"], "text", "Telegram takes HTML, but only a few tags")
        page = self.calls[0]["body"]
        self.assertTrue(page.startswith("<!doctype html>"), "a whole document, so its style sheet is kept")
        self.assertIn("prefers-color-scheme:dark", page)
        self.assertIn('<body class="mail" style="margin:16px;', page)
        self.assertIn(".mail{margin:0!important}", page, "on a phone, the mail app pads it")
        self.assertNotIn("data:image", page, "graphs by reference in email")

    def test_narrow_screens(self):
        report = {"title": "Daily summary", "span": "a to b", "sections": [
            {"title": "Current status", "head": None, "graphs": [],
             "rows": [["WAN address", "2001:db8::1"], ["6 of 6 interface links up"]]}]}
        body = summary.summary_html(report, {})
        self.assertIn('<td class="label" style="', body)
        self.assertEqual(body.count("white-space:nowrap"), 1, "a line on its own may wrap")
        self.assertEqual(body.count("overflow-wrap:anywhere"), 3)

    def test_the_short_text_links_to_the_report(self):
        folder = tempfile.mkdtemp()
        saved = summary.REPORTS_DIR
        summary.REPORTS_DIR = folder
        summary.draw_graph = lambda spec, directory: None
        try:
            item = dict(notify.message("summary", "info", "Daily summary", "fw · a to b"), uuid=CHANNEL,
                        report=self.REPORT)
            self.assertNotIn("Full report", notify.archived({"general": {}}, item, "daily", 0)["body"],
                             "no address known")
            config = {"general": {}, "guiUrl": "https://fw.example.lan"}
            item = notify.archived(config, item, "daily", 0)
            self.assertEqual(item["body"].splitlines(), [
                "fw · a to b", f"Full report: <https://fw.example.lan/ui/notify/report/view/{item['archive']}>"],
                "bracketed, so a ping appended after it stays out of the link")
            config["general"]["reportAddress"] = "https://vpn.example.net:8443/"
            self.assertIn("Full report: <https://vpn.example.net:8443/ui/notify/report/view/",
                          notify.archived(config, dict(item, body="short"), "daily", 60)["body"])
            notify.deliver({"uuid": CHANNEL, "url": "tgram://123456789:abcdefg_hijklmnop/1"}, "t", item["body"], "info",
                           self.REPORT)
        finally:
            summary.REPORTS_DIR = saved
            shutil.rmtree(folder)
        self.assertIsNone(self.calls[0].get("attach"), "a link, not a file")


class Delivery(unittest.TestCase):
    def test_queued_digest_follows_the_subscription(self):
        found = [notify.message("gateway", "failure", "a", ""), notify.message("ids", "warning", "b", "")]
        item = notify.digest([dict(m, uuid=CHANNEL) for m in found], 2)[0]
        self.assertEqual(item["events"], ["gateway", "ids"])
        self.assertTrue(notify.wants({"events": ["ids"]}, item))
        self.assertFalse(notify.wants({"events": ["config"]}, item))
        self.assertTrue(notify.wants({"events": ["config"]}, {"event": "digest"}), "queued before events were kept")

    def test_unreadable_settings_keep_the_state(self):
        folder = tempfile.mkdtemp()
        saved = notify.STATE, notify.load_config
        try:
            notify.STATE = os.path.join(folder, "state.json")
            with open(notify.STATE, "w") as handle:
                handle.write("{}")
            reads = iter([None, {"general": {"enabled": "0"}, "channels": [], "hostname": ""}])
            notify.load_config = lambda: next(reads)
            notify.run_check()
            self.assertTrue(os.path.exists(notify.STATE), "a failed read is not a switch-off")
            notify.run_check()
            self.assertFalse(os.path.exists(notify.STATE), "switched off: start afresh")
        finally:
            notify.STATE, notify.load_config = saved
            shutil.rmtree(folder)


class Commands(unittest.TestCase):
    def tearDown(self):
        notify.interfaces.cache_clear()

    def test_stray_bytes_do_not_stop_a_command_being_read(self):
        self.assertEqual(notify.command_output(["/bin/sh", "-c", "printf 'caf\\351 ok'"]), "caf\ufffd ok")

    def test_the_repeat_hold_is_bounded(self):
        folder = tempfile.mkdtemp()
        saved = notify.SYSLOG_DIR
        try:
            notify.SYSLOG_DIR = folder
            os.makedirs(os.path.join(folder, "system"))
            path = os.path.join(folder, "system", f"system_{notify.time.strftime('%Y%m%d')}.log")
            with open(path, "w") as handle:
                handle.write("")
            state, _ = notify.check_syslog({"general": {}}, None)
            state["seen"] = {f"old\t{i}": notify.time.time() - 60 for i in range(notify.SEEN_MAX)}
            with open(path, "a") as handle:
                handle.write('<10>1 2026-09-27T10:00:00+10:00 fw kernel 1 - - disk failing\n')
            state, _ = notify.check_syslog({"general": {}}, state)
        finally:
            notify.SYSLOG_DIR = saved
            shutil.rmtree(folder)
        self.assertEqual(len(state["seen"]), notify.SEEN_MAX)
        self.assertIn("kernel\tdisk failing", state["seen"], "the newest are kept")

    def test_a_repeat_is_held_unless_more_severe(self):
        folder = tempfile.mkdtemp()
        saved = notify.SYSLOG_DIR
        config = {"general": {"logSeverity": "4"}}
        sent = []
        try:
            notify.SYSLOG_DIR = folder
            os.makedirs(os.path.join(folder, "system"))
            path = os.path.join(folder, "system", f"system_{notify.time.strftime('%Y%m%d')}.log")
            with open(path, "w") as handle:
                handle.write("")
            state, _ = notify.check_syslog(config, None)
            # critical then warning; warning then critical; 10 is critical, 12 a warning
            for priority, text in ((10, "disk failing"), (12, "disk failing"), (12, "fan slow"), (10, "fan slow"),
                                   (12, "fan slow")):
                with open(path, "a") as handle:
                    handle.write(f"<{priority}>1 2026-09-27T10:00:00+10:00 fw kernel 1 - - {text}\n")
                state, messages = notify.check_syslog(config, state)
                sent.append(len([m for m in messages if not m.get("quiet")]))
            state["levels"] = {}  # as saved before levels were kept
            with open(path, "a") as handle:
                handle.write("<10>1 2026-09-27T10:00:00+10:00 fw kernel 1 - - fan slow\n")
            state, messages = notify.check_syslog(config, state)
            sent.append(len([m for m in messages if not m.get("quiet")]))
        finally:
            notify.SYSLOG_DIR = saved
            shutil.rmtree(folder)
        self.assertEqual(sent, [1, 0, 1, 1, 0, 0])

    def test_only_a_command_that_succeeded_counts(self):
        self.assertEqual(notify.command_output(["/bin/sh", "-c", "echo ok"]), "ok\n")
        self.assertIsNone(notify.command_output(["/bin/sh", "-c", "echo partial; exit 1"]))
        self.assertEqual(notify.command_output(["/bin/sh", "-c", "echo partial; exit 1"], partial=True), "partial\n")
        self.assertIsNone(notify.command_output(["/nonexistent"]))

    def test_firmware_changes_as_the_firmware_page_lists_them(self):
        check = {"connection": "ok", "upgrade_packages": [{"name": "a", "current_version": "1", "new_version": "2"}],
                 "new_packages": [{"name": "b", "version": "3"}], "remove_packages": [{"name": "c", "version": "4"}],
                 "reinstall_packages": [{"name": "d", "version": "5"}]}
        saved = notify.read_firmware
        notify.read_firmware = lambda: check
        try:
            state, messages = notify.check_firmware({}, None)
            self.assertEqual(messages[0]["body"].splitlines(), ["a 1 -> 2", "b 3 (new)", "d 5 (reinstall)",
                                                                "c 4 (obsolete)"])
            self.assertIn('"a-2", "b-3"', state["key"], "keys as before for upgrades and new ones")
            self.assertEqual(notify.check_firmware({}, dict(state, checked=0))[1], [], "once")
            check["new_packages"].append({"name": "e", "version": "6"})
            self.assertEqual(notify.check_firmware({}, state)[1], [], "read at most every 5 minutes")
            self.assertEqual(len(notify.check_firmware({}, state["key"])[1]), 1, "a key saved before: read now")
        finally:
            notify.read_firmware = saved

    def test_state_table_as_the_widget_reads_it(self):
        saved = common.configctl
        try:
            common.configctl = lambda *args: "current 1234\nlimit 100000\n" if args == ("filter", "diag", "state_size") \
                else None
            notify.pf_states.cache_clear()
            self.assertEqual(notify.pf_states(), (1234, 100000))
            common.configctl = lambda *args: None
            notify.pf_states.cache_clear()
            self.assertIsNone(notify.pf_states())
        finally:
            common.configctl = saved
            notify.pf_states.cache_clear()

    def test_interfaces_as_core_reads_them(self):
        # core's `interface list ifconfig`, as pluginctl -D answers
        found = {"vtnet0": {"status": "active", "ipv4": [{"ipaddr": "192.0.2.1", "vhid": "1"}],
                            "ipv6": [{"ipaddr": "2001:db8::1", "deprecated": False, "link-local": False},
                                     {"ipaddr": "2001:db8::2", "deprecated": True, "link-local": False},
                                     {"ipaddr": "fe80::1", "link-local": True}],
                            "carp": {"1": {"status": "MASTER", "vhid": "1", "advbase": "1", "advskew": "0"}}},
                 "lo0": {"ipv4": [{"ipaddr": "127.0.0.1"}], "ipv6": []}}
        saved = common.configctl_json
        common.configctl_json = lambda *args: found if args == ("interface", "list", "ifconfig") else None
        notify.interfaces.cache_clear()
        try:
            self.assertEqual(notify.addresses(), {"vtnet0": ["192.0.2.1", "2001:db8::1"]})
            self.assertEqual(notify.link_states({"vtnet0": "WAN", "lo0": "lo"}), {"vtnet0": "active"})
            self.assertEqual(notify.carp_vhids(), [("vtnet0", "1", "MASTER")])
            _, messages = notify.check_carp({"interfaces": {"vtnet0": "WAN"}}, {"1@vtnet0": "BACKUP"})
            self.assertEqual([m["title"] for m in messages], ["CARP vhid 1 on WAN is now MASTER"])
        finally:
            common.configctl_json = saved

    def test_no_interfaces_reading_is_not_no_interfaces(self):
        saved = common.command_output
        common.command_output = lambda command, timeout=30, partial=False: None
        notify.interfaces.cache_clear()
        try:
            self.assertTrue(notify.is_carp_backup({"general": {"carpMasterOnly": "1"}}), "quiet when it cannot tell")
            self.assertFalse(notify.is_carp_backup({"general": {}}))
            self.assertFalse(notify.is_carp_backup({"general": {"carpMasterOnly": "1"}}, unknown=False),
                             "the startup notice is sent rather than lost")
        finally:
            common.command_output = saved

    def test_a_rotated_log_that_is_gone_starts_the_new_one(self):
        folder, elsewhere = tempfile.mkdtemp(), tempfile.mkdtemp()
        try:
            path = os.path.join(folder, "eve.json")
            with open(path, "w") as handle:
                handle.write("x\n")
            _, state, _ = notify.follow(path, {})
            # rotated and compressed: out of reach, and still holding its inode, as a file system
            # would otherwise hand it straight to the new log
            os.rename(path, os.path.join(elsewhere, "eve.json.0.gz"))
            with open(path, "w") as handle:
                handle.write('{"event_type":"alert"}\n')
            lines, _, (missed, _) = notify.follow(path, state, b'"event_type":"alert"')
        finally:
            shutil.rmtree(folder)
            shutil.rmtree(elsewhere)
        self.assertEqual((len(lines), missed), (1, 0), "no false alarm each rotation")

    def test_a_line_still_being_written_waits(self):
        folder = tempfile.mkdtemp()
        try:
            path = os.path.join(folder, "eve.json")
            for keep in (b'"event_type":"alert"', None):
                with open(path, "w") as handle:
                    handle.write('{"event_type":"alert","n":1}\n{"event_type":"alert","n":')
                lines, _, _, end = notify.read_new(path, 0, keep)
                self.assertEqual(len(lines), 1)
                with open(path, "a") as handle:
                    handle.write('2}\n')
                lines = notify.read_new(path, end, keep)[0]
                self.assertEqual([json.loads(line)["n"] for line in lines], [2], "read whole next time")
        finally:
            shutil.rmtree(folder)

    def test_marker_scan_finds_lines_across_blocks(self):
        folder = tempfile.mkdtemp()
        try:
            path = os.path.join(folder, "eve.json")
            filler = b'{"event_type":"flow"}' + b" " * 200 + b"\n"
            with open(path, "wb") as handle:
                for i in range(30000):  # about 6.6 MB: more than one block
                    handle.write(filler if i % 7000 else b'{"event_type":"alert","n":%d}\n' % i)
                handle.write(b'{"event_type":"alert","n":"last, no newline"}')
            lines = notify.read_new(path, 0, b'"event_type":"alert"')[0]
        finally:
            shutil.rmtree(folder)
        self.assertEqual([json.loads(line)["n"] for line in lines], [0, 7000, 14000, 21000, 28000],
                         "the unfinished last line waits")

    def test_a_malformed_alert_is_skipped(self):
        folder = tempfile.mkdtemp()
        saved = notify.IDS_LOG
        try:
            notify.IDS_LOG = os.path.join(folder, "eve.json")
            with open(notify.IDS_LOG, "w") as handle:
                handle.write("")
            state, _ = notify.check_ids({"general": {"idsSeverity": "3"}}, None)
            with open(notify.IDS_LOG, "a") as handle:
                handle.write('{"event_type":"alert","alert":{"severity":"high","signature":"bad"}}\n')
                handle.write('{"event_type":"alert","alert":{"severity":1,"signature":"ET SCAN"}}\n')
            state, messages = notify.check_ids({"general": {"idsSeverity": "3"}}, state)
        finally:
            notify.IDS_LOG = saved
            shutil.rmtree(folder)
        self.assertEqual([m["title"] for m in messages], ["ET SCAN"])


class LogMessages(unittest.TestCase):
    LINE = '<{pri}>1 2026-09-27T10:00:00+10:00 fw.example {prog} 123 - [meta sequenceId="1"] {text}\n'

    def setUp(self):
        self.folder = tempfile.mkdtemp()
        self.saved = notify.SYSLOG_DIR
        notify.SYSLOG_DIR = self.folder
        for name in ("system", "notify"):
            os.makedirs(os.path.join(self.folder, name))
        self.day = notify.time.strftime("%Y%m%d")

    def tearDown(self):
        notify.SYSLOG_DIR = self.saved
        shutil.rmtree(self.folder)

    def write(self, name, lines):
        with open(os.path.join(self.folder, name, f"{name}_{self.day}.log"), "a") as handle:
            handle.writelines(lines)

    def test_critical_and_above_once_an_hour(self):
        self.write("system", [self.LINE.format(pri=13, prog="x", text="start")])
        self.write("notify", [self.LINE.format(pri=11, prog="notify", text="could not send")])
        config = {"general": {"logSeverity": "2"}}
        state, messages = notify.check_syslog(config, None)
        self.assertEqual(messages, [], "the first pass sets the baseline")
        self.write("system", [self.LINE.format(pri=10, prog="kernel", text="disk failing"),     # 10 % 8 = critical
                              self.LINE.format(pri=10, prog="kernel", text="disk failing"),
                              self.LINE.format(pri=11, prog="unbound", text="error only"),      # error: below the level
                              self.LINE.format(pri=13, prog="cron", text="notice")])
        self.write("notify", [self.LINE.format(pri=10, prog="notify", text="its own log is not read")])
        state, messages = notify.check_syslog(config, state)
        self.assertEqual([m["title"] for m in messages], ["kernel: disk failing"])
        self.assertIn("Critical in the system log: disk failing", messages[0]["body"])
        self.assertIn("(Logged 2 times.)", messages[0]["body"])
        self.assertEqual(messages[0]["facts"], {"program": "kernel"})
        self.write("system", [self.LINE.format(pri=10, prog="kernel", text="disk failing")] * 3)
        _, messages = notify.check_syslog(config, state)
        self.assertEqual([(m.get("quiet"), m["count"]) for m in messages], [(True, 3)],
                         "held for an hour, but still counted")
        channel = {"uuid": CHANNEL, "events": ["syslog"], "summaryEvents": ["syslog"]}
        self.assertFalse(notify.wants(channel, messages[0]), "not sent")
        note = notify.left_out("syslog", "log messages", 5, 0)[0]
        period = summary.add_events({}, channel, messages + [note])
        self.assertEqual(period["events"], {"syslog": 3}, "the repeats count, the note does not")
        self.assertEqual(period["facts"]["syslog"]["program"], {"kernel": 3})
        self.assertEqual(period["recent"], [], "not listed as a latest event")

    def test_the_not_checked_note_is_held(self):
        self.write("system", [])
        config = {"general": {}}
        state, _ = notify.check_syslog(config, None)
        saved = notify.LOG_LINES
        notify.LOG_LINES = 1
        try:
            notes = []
            for _ in range(2):
                self.write("system", [self.LINE.format(pri=10, prog="kernel", text=f"disk {i}") for i in range(3)])
                state, messages = notify.check_syslog(config, state)
                notes.append([m["title"] for m in messages if m.get("note")])
        finally:
            notify.LOG_LINES = saved
        self.assertEqual(notes, [["Some log messages were not checked"], []], "once an hour, like the messages")

    def test_error_level(self):
        self.write("system", [])
        config = {"general": {"logSeverity": "3"}}
        state, _ = notify.check_syslog(config, None)
        self.write("system", [self.LINE.format(pri=11, prog="unbound", text="error now")])
        _, messages = notify.check_syslog(config, state)
        self.assertEqual([m["type"] for m in messages], ["warning"])


class SummaryFacts(unittest.TestCase):
    def test_top_details_are_tallied_and_listed(self):
        channel = {"uuid": CHANNEL, "summary": "daily", "summaryEvents": ["ids", "vpn"], "summarySections": []}
        found = [summary.message("ids", "warning", "ET SCAN", "", {"signature": "ET SCAN", "source": "198.51.100.4"}),
                 summary.message("ids", "warning", "ET SCAN", "", {"signature": "ET SCAN", "source": "203.0.113.9"}),
                 summary.message("vpn", "warning", "wg is stale", "", {"peer": "WireGuard wg0 abc: stale"}),
                 summary.message("auth", "warning", "Failed login", "", {"outcome": "Failed"})]
        period = summary.add_events({"since": 0, "schedule": "daily"}, channel, found)
        self.assertEqual(period["facts"]["ids"]["signature"], {"ET SCAN": 2})
        self.assertNotIn("auth", period["facts"], "only the channel's summary events")
        item = summary.build_summary({"eventLabels": {}, "hostname": "fw.example"}, channel, period, 100)
        rows = {part["title"]: part["rows"] for part in item["report"]["sections"]}
        self.assertEqual(rows["Intrusion detection: top signatures"], [["ET SCAN", "2"]])
        self.assertIn("Intrusion detection: top sources", rows)
        self.assertEqual(rows["VPN peers"], [["WireGuard wg0 abc: stale", "1"]])
        self.assertTrue(item["body"].startswith("fw.example · "), "the host name says which firewall")

    def test_pies_color_their_rows(self):
        saved = summary.configctl_json
        summary.configctl_json = lambda *a: [{"id": f"r{i}", "descr": f"Rule {i}"} for i in range(7)]
        try:
            channel = {"uuid": CHANNEL, "summary": "daily", "summaryEvents": [], "summarySections": ["firewall", "traffic"]}
            totals = {"if a in_pass bytes": 300, "if b in_pass bytes": 100, "if a in_block packets": 5}
            totals.update({f"rule r{i}": 100 - i for i in range(7)})
            item = summary.build_summary({"interfaces": {"a": "WAN", "b": "LAN"}}, channel,
                                        {"since": 0, "schedule": "daily", "totals": totals}, 100)
        finally:
            summary.configctl_json = saved
        parts = {part["title"]: part for part in item["report"]["sections"]}
        self.assertNotIn("pie", parts["Firewall blocks"], "one interface is not a pie")
        rules = parts["Block rules matched most"]
        self.assertEqual(rules["rows"][-1], ["Other rules", "189"])
        self.assertEqual(rules["swatches"][-1], chart.PIE_OTHER)
        self.assertEqual([v for v, _ in rules["pie"]["slices"]], [100, 99, 98, 97, 96, 189])
        self.assertEqual(parts["Traffic"]["pie"]["slices"], [[300, chart.PIE_COLORS[0]], [100, chart.PIE_COLORS[1]]])
        body = summary.summary_html(item["report"], {"pie-traffic.png": {"path": "/x", "legend": []}})
        self.assertIn('<img src="cid:pie-traffic.png"', body)
        self.assertIn(f'<span style="color:{chart.PIE_COLORS[1]}">&#9632;</span>&nbsp;LAN', body)
        image = chart.donut_png([(3, "#4e79a7"), (1, "#bab0ac")])
        self.assertEqual(chart.struct.unpack(">II", image[16:24]), (chart.PIE_SIZE, chart.PIE_SIZE))

    def test_each_channel_gets_its_own_pie(self):
        summary.GRAPHS.clear()
        saved = summary.draw_graph
        summary.draw_graph = lambda spec, directory: {"path": os.path.join(directory, spec["name"]), "legend": []}
        try:
            one = summary.drawn_graph({"kind": "pie", "name": "pie-traffic.png", "slices": [[3, "#4e79a7"], [1, "#f28e2b"]],
                                       "start": 0, "end": 1, "title": "Traffic"})
            two = summary.drawn_graph({"kind": "pie", "name": "pie-traffic.png", "slices": [[1, "#4e79a7"], [1, "#f28e2b"]],
                                       "start": 0, "end": 1, "title": "Traffic"})
        finally:
            summary.draw_graph = saved
            summary.GRAPHS.clear()
        self.assertNotEqual(one["path"], two["path"])

    def test_addresses_are_not_figures(self):
        report = {"title": "t", "span": "s", "sections": [
            {"title": "Logins: top sources", "head": ["Source", "Count"], "rows": [["198.51.100.4", "3"]],
             "graphs": []},
            {"title": "Traffic", "head": ["Interface", "In"], "rows": [["WAN", "2.5 MB"]], "graphs": []}]}
        body = summary.summary_html(report, {})
        self.assertIn('text-align:left">198.51.100.4', body)
        self.assertIn('text-align:right">2.5 MB', body)

    def test_wireguard_as_core_names_it(self):
        now = int(notify.time.time())
        saved = notify.configctl_json
        records = [{"type": "peer", "if": "wg0", "public-key": "a" * 44, "latest-handshake": now - 30},
                   {"type": "peer", "if": "wg0", "public-key": "b" * 44, "latest-handshake": now - 900},
                   {"type": "peer", "if": "wg0", "public-key": "c" * 44, "latest-handshake": 0}]
        notify.configctl_json = lambda *a: {"records": records} if a[0] == "wireguard" else {}
        try:
            before = {f"WireGuard wg0 {k * 12}": "down" for k in "abc"}
            state, messages = notify.check_vpn({}, before)
        finally:
            notify.configctl_json = saved
        self.assertEqual(sorted(state.values()), ["offline", "online", "stale"])
        self.assertEqual([m["title"] for m in messages], [f"WireGuard wg0 {'a' * 12} is online"],
                         "down as recorded before 1.4 covered both stale and never connected")

    def test_an_unread_vpn_status_is_not_everyone_gone(self):
        saved = notify.configctl_json
        before = {"WireGuard wg0 aaaaaaaaaaaa": "online", "OpenVPN client 1": "up",
                  "OpenVPN server 2 alice": "up"}
        try:
            for failed in ("wireguard", "openvpn"):
                notify.configctl_json = lambda *a, failed=failed: None if a[0] == failed else {}
                state, messages = notify.check_vpn({}, before)
                self.assertEqual({k: v for k, v in state.items() if failed in k.lower()},
                                 {k: v for k, v in before.items() if failed in k.lower()}, failed)
                self.assertFalse([m for m in messages if failed in m["title"].lower()], failed)
        finally:
            notify.configctl_json = saved


class Services(unittest.TestCase):
    PATCHED = ("service_states", "carp_states", "booting_or_updating", "is_carp_backup", "time")

    def setUp(self):
        self.saved = {name: getattr(notify, name) for name in self.PATCHED}
        self.folder = tempfile.mkdtemp()
        self.now, self.uptime, self.carp, self.busy, self.backup = 1_790_000_000, 100_000.0, [], False, False
        self.services = [["unbound/", "Unbound DNS", True]]
        notify.service_states = lambda: [tuple(x) for x in self.services]
        notify.carp_states = lambda: self.carp
        notify.booting_or_updating = lambda: self.busy
        notify.is_carp_backup = lambda config, unknown=True: self.backup
        notify.time = type("Clock", (), {"time": lambda _=None: self.now, "monotonic": lambda _=None: self.uptime,
                                         "strftime": time_module.strftime, "localtime": time_module.localtime})()

    def tearDown(self):
        for name, value in self.saved.items():
            setattr(notify, name, value)
        shutil.rmtree(self.folder)

    def run_checks(self, state, minutes, running=False):
        """Checks a minute apart with Unbound running or not: (state, messages)."""
        self.services[0][2] = running
        found = []
        for _ in range(minutes):
            self.now += 60
            self.uptime += 60
            state, messages = notify.check_service({}, state)
            found += messages
        return state, found

    def titles(self, messages):
        return [m["title"] for m in messages]

    def reboot(self):
        self.uptime = 30.0

    def test_stopped_past_the_hold_and_back(self):
        state, messages = notify.check_service({}, None)
        self.assertEqual(messages, [], "the first sight only records")
        state, messages = self.run_checks(state, 1)
        state, more = self.run_checks(state, 1, running=True)
        self.assertEqual(messages + more, [], "a restart between checks")
        state, messages = self.run_checks(state, 4)
        self.assertEqual(messages, [], "within the hold")
        state, messages = self.run_checks(state, 3)
        self.assertEqual(self.titles(messages), ["Unbound DNS has stopped"], "once, past the hold")
        state, messages = self.run_checks(state, 1, running=True)
        self.assertEqual(self.titles(messages), ["Unbound DNS is running again"])
        self.assertTrue(messages[0].get("note"), "its end is sent, not counted as another stop")

    def test_first_sight_is_not_a_boot(self):
        self.services[0][2] = False
        state, _ = notify.check_service({}, None)
        state, messages = self.run_checks(state, 6)
        self.assertEqual(self.titles(messages), ["Unbound DNS has stopped"])
        self.assertTrue(messages[0]["body"].endswith(" or earlier."), "stopped before it was first seen")

    def test_the_hold_runs_on_uptime(self):
        state, _ = notify.check_service({}, None)
        state, _ = self.run_checks(state, 1)
        self.now += 7200  # stepped by NTP
        state, messages = self.run_checks(state, 1)
        self.assertEqual(messages, [], "a clock step does not end the hold")
        state, messages = self.run_checks(state, 4)
        self.assertEqual(self.titles(messages), ["Unbound DNS has stopped"])

    def test_after_a_reboot(self):
        state, _ = notify.check_service({}, None)
        state, messages = self.run_checks(state, 20)
        self.assertEqual(self.titles(messages), ["Unbound DNS has stopped"])
        self.reboot()
        state, messages = self.run_checks(state, 10)
        self.assertEqual(messages, [], "reported before the reboot, so not again")
        state, messages = self.run_checks(state, 1, running=True)
        self.assertEqual(self.titles(messages), ["Unbound DNS is running again"], "its end still comes")
        state, _ = self.run_checks(state, 1)
        self.reboot()
        state, messages = self.run_checks(state, 1)
        self.assertEqual(messages, [], "a reboot only records")
        state, messages = self.run_checks(state, 6)
        self.assertEqual(self.titles(messages), ["Unbound DNS is not running after boot"])

    def test_gone_from_one_read_is_not_closed(self):
        state, _ = notify.check_service({}, None)
        state, messages = self.run_checks(state, 7)
        self.assertEqual(self.titles(messages), ["Unbound DNS has stopped"])
        self.services.append(["dhcpd/", "DHCP", True])
        unbound = self.services.pop(0)
        state, messages = self.run_checks(state, 1, running=True)
        self.assertEqual(messages, [], "one read without it")
        self.services.insert(0, unbound)
        state, messages = self.run_checks(state, 7)
        self.assertEqual(messages, [], "still the stop already reported")
        self.services.pop(0)
        state, messages = self.run_checks(state, 2, running=True)
        self.assertEqual(self.titles(messages), ["Unbound DNS is no longer listed"])

    def test_running_after_boot_then_stopped(self):
        state, _ = notify.check_service({}, None)
        self.reboot()
        state, _ = self.run_checks(state, 2, running=True)
        state, messages = self.run_checks(state, 7)
        self.assertEqual(self.titles(messages), ["Unbound DNS has stopped"], "seen running since boot")

    def test_an_end_on_a_standby_is_sent(self):
        state, _ = notify.check_service({}, None)
        state, messages = self.run_checks(state, 7)
        self.assertEqual(self.titles(messages), ["Unbound DNS has stopped"])
        self.carp = ["BACKUP"]  # failed over; CARP master only is off, so this node still sends
        state, messages = self.run_checks(state, 1, running=True)
        self.assertEqual(self.titles(messages), ["Unbound DNS is running again"], "not held for the next promotion")
        state, messages = self.run_checks(state, 10)
        self.assertEqual(messages, [], "a standby reports no stop")

    def test_no_state_soon_after_boot_is_not_a_recent_check(self):
        self.uptime = 600.0
        self.services[0][2] = False
        state, _ = notify.check_service({}, None)
        self.assertTrue(state["services"]["unbound/"]["late"], "when it stopped is not known")

    def test_a_pause_times_a_stop_again(self):
        state, _ = notify.check_service({}, None)
        state, _ = self.run_checks(state, 1)
        self.now, self.uptime = self.now + 7200, self.uptime + 7200  # checks paused, no reboot
        state, messages = self.run_checks(state, 1)
        self.assertEqual(messages, [], "not long past its hold on one sight")
        state, messages = self.run_checks(state, 5)
        self.assertEqual(self.titles(messages), ["Unbound DNS has stopped"])
        self.assertTrue(messages[0]["body"].endswith(" or earlier."), "when it stopped is not known")

    def test_held_back_by_firmware_and_carp(self):
        state, _ = notify.check_service({}, None)
        self.busy = True
        state, messages = self.run_checks(state, 20)
        self.busy = False
        state, more = self.run_checks(state, 3)
        self.assertEqual(messages + more, [], "the hold starts over after an update")
        self.carp = ["MASTER"]
        state, messages = self.run_checks(state, 4)
        self.assertEqual(messages, [], "a role change holds reports back")
        state, messages = self.run_checks(state, 2)
        self.assertEqual(self.titles(messages), ["Unbound DNS has stopped"])
        at = state["services"]["unbound/"]["at"]
        self.busy = True
        self.carp = ["MASTER", "INIT"]
        state, _ = self.run_checks(state, 2)
        self.busy = False
        self.assertEqual((state["services"]["unbound/"]["at"], state["role"]), (at, "master"),
                         "once reported, how long is kept; a flapping address is no change of role")

    def test_quiet_on_a_standby(self):
        self.carp = ["BACKUP"]
        state, _ = notify.check_service({}, None)
        state, messages = self.run_checks(state, 20)
        self.assertEqual(messages, [], "a standby stops some services with its role")
        state, messages = self.run_checks(state, 1, running=True)
        self.assertEqual(messages, [], "so nothing to say it is back")
        self.carp = ["INIT"]
        state, _ = notify.check_service({}, None)
        state, messages = self.run_checks(state, 7)
        self.assertEqual(self.titles(messages), ["Unbound DNS has stopped"], "INIT alone is no standby")

    def test_a_five_minute_interval(self):
        state, _ = notify.check_service({}, None)
        self.services[0][2] = False
        self.now, self.uptime = self.now + 300, self.uptime + 300.9  # a slow service list
        state, _ = notify.check_service({}, state)
        self.now, self.uptime = self.now + 300, self.uptime + 299.5
        state, messages = notify.check_service({}, state)
        self.assertEqual(self.titles(messages), ["Unbound DNS has stopped"], "on the second check, not the third")

    def test_firmware_keeps_the_stop_time(self):
        state, _ = notify.check_service({}, None)
        state, _ = self.run_checks(state, 3)
        self.busy = True
        state, _ = self.run_checks(state, 1)
        self.busy = False
        state, messages = self.run_checks(state, 5)
        self.assertEqual(self.titles(messages), ["Unbound DNS has stopped"], "the hold started over")
        self.assertEqual(messages[0]["body"], f"Stopped since {notify.clock(self.now - 480)}.", "the stop kept its time")

    def test_not_asked_while_all_run(self):
        asked = []
        notify.booting_or_updating = lambda: asked.append(1) or False
        state, _ = notify.check_service({}, None)
        self.run_checks(state, 3, running=True)
        self.assertEqual(asked, [], "only asked while a stop is timed")

    def test_back_and_down_again_while_silent(self):
        state, _ = notify.check_service({}, None)
        state, _ = self.run_checks(state, 7)
        self.backup = True
        state, _ = self.run_checks(state, 10, running=True)
        state, messages = self.run_checks(state, 20)
        self.assertEqual(messages, [], "silent")
        self.backup = False
        state, messages = self.run_checks(state, 1)
        self.assertEqual([(m["title"], m["body"][:15]) for m in messages],
                         [("Unbound DNS is running again", "Stopped for 7m."), ("Unbound DNS has stopped", "Stopped since 2")],
                         "the first stop ends as it did, then the second, long past its hold, is its own")

    def test_an_end_kept_across_a_reboot(self):
        state, _ = notify.check_service({}, None)
        state, _ = self.run_checks(state, 7)
        self.backup = True
        state, _ = self.run_checks(state, 3, running=True)
        self.reboot()
        state, messages = self.run_checks(state, 2, running=True)
        self.assertEqual(messages, [], "still silent")
        self.backup = False
        state, messages = self.run_checks(state, 1, running=True)
        self.assertEqual([(m["title"], m["body"]) for m in messages], [("Unbound DNS is running again", "Stopped for 7m.")])

    def test_old_state_is_kept(self):
        folder = tempfile.mkdtemp()
        saved = notify.STATE
        try:
            notify.STATE = os.path.join(folder, "state.json")
            with open(notify.STATE, "w") as handle:
                json.dump({"stamp": 0, "service": {"services": {}}, "gateway": {}}, handle)
            self.assertEqual(notify.fresh_state(), {"service": {"services": {}}}, "what it sends later still wants it")
        finally:
            notify.STATE = saved
            shutil.rmtree(folder)

    def test_unlisted_while_silent(self):
        state, _ = notify.check_service({}, None)
        state, _ = self.run_checks(state, 7)
        self.backup = True
        notify.service_states = lambda: [("dhcpd/", "DHCP", True)]
        state, messages = notify.check_service({}, state)
        self.assertEqual((messages, state["services"]["unbound/"]["reported"]), ([], True), "kept until it can be said")
        self.backup = False
        state, messages = notify.check_service({}, state)
        self.assertEqual(messages, [], "one read without it")
        state, messages = notify.check_service({}, state)
        self.assertEqual(self.titles(messages), ["Unbound DNS is no longer listed"])

    def test_times_from_uptime(self):
        state, _ = notify.check_service({}, None)
        state, _ = self.run_checks(state, 7)
        self.now -= 86400  # stepped back a day
        state, messages = self.run_checks(state, 1, running=True)
        self.assertEqual(messages[0]["body"], "Stopped for 7m.", "not moved by the clock")

    def test_nothing_marked_while_not_sent(self):
        state, _ = notify.check_service({}, None)
        state, messages = self.run_checks(state, 7)
        self.assertEqual(self.titles(messages), ["Unbound DNS has stopped"])
        self.backup = True  # CARP master only, and now the backup: what it finds is not sent
        state, messages = self.run_checks(state, 2, running=True)
        self.assertEqual(messages, [], "silent")
        self.backup = False
        state, messages = self.run_checks(state, 1, running=True)
        self.assertEqual(self.titles(messages), ["Unbound DNS is running again"], "its end when sending again")
        self.backup = True
        state, messages = self.run_checks(state, 10)
        self.assertEqual((messages, state["services"]["unbound/"].get("reported")), ([], None),
                         "a stop found while silent is not marked sent")

    def test_removed_after_its_stop(self):
        state, _ = notify.check_service({}, None)
        state, _ = self.run_checks(state, 7)
        notify.service_states = lambda: [("dhcpd/", "DHCP", True)]
        state, messages = notify.check_service({}, state)
        self.assertEqual(messages, [], "one read without it")
        state, messages = notify.check_service({}, state)
        self.assertEqual(self.titles(messages), ["Unbound DNS is no longer listed"], "not left open")
        self.assertTrue(messages[0].get("note"))
        state, messages = notify.check_service({}, state)
        self.assertEqual(messages, [], "said once")

    def test_unread_or_gone(self):
        state, _ = notify.check_service({}, None)
        state, _ = self.run_checks(state, 3)
        notify.service_states = lambda: None
        self.assertEqual(notify.check_service({}, state), (state, []), "an unread list changes nothing")
        notify.service_states = lambda: []
        self.assertEqual(notify.check_service({}, state), (state, []), "nor an empty one")
        notify.service_states = lambda: [("dhcpd/", "DHCP", True)]
        state, messages = notify.check_service({}, state)
        self.assertEqual((list(state["services"]), messages), (["dhcpd/"], []), "disabled before it was reported: no word")

    def test_the_widget_rules(self):
        saved = common.configctl_json
        try:
            for answer, expected in [({}, []), (None, None), ([
                    {"name": "openvpn", "id": "1", "description": "OpenVPN client", "status": "openvpn is not running."},
                    {"name": "pf", "description": "Packet Filter", "nocheck": True, "status": "pf is running."},
                    {"name": "x", "description": "X", "status": "x is running."},
                    {"name": "x", "description": "X", "status": "x is not running."}],
                    [("openvpn/1", "OpenVPN client", False), ("x/", "X", True), ("x/#2", "X", False)])]:
                common.service_states.cache_clear()
                common.configctl_json = lambda *a, answer=answer: answer
                self.assertEqual(common.service_states(), expected, answer)
        finally:
            common.configctl_json = saved
            common.service_states.cache_clear()


class Hardening(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.mkdtemp()
        self.saved = {name: getattr(notify, name) for name in ("STATE", "load_config", "interfaces", "is_carp_backup",
                                                               "update_summaries", "COLLECTORS")}
        notify.STATE = os.path.join(self.folder, "state.json")
        notify.load_config = lambda: {"general": {"enabled": "1"}, "channels": [
            {"uuid": CHANNEL, "enabled": "1", "events": [], "summary": "daily", "summaryEvents": [], "summarySections": []}],
            "hostname": "fw"}
        notify.COLLECTORS = ()

    def tearDown(self):
        for name, value in self.saved.items():
            setattr(notify, name, value)
        shutil.rmtree(self.folder)

    def test_a_standby_keeps_periods_until_due(self):
        now = int(notify.time.time())
        boundary = summary.last_boundary(now, "daily", 7, 1)
        periods = {CHANNEL: {"since": boundary + 1, "schedule": "daily"}}  # started after the last summary
        notify.save_state({"stamp": now, "summary": {"sampled": now, "channels": dict(periods)}})
        notify.interfaces = lambda: {}
        notify.is_carp_backup = lambda config, unknown=True: True
        notify.update_summaries = lambda *a: self.fail("counters are not due yet")
        notify.run_check()
        self.assertEqual(notify.load_state()["summary"]["channels"], periods, "a brief flap loses nothing")
        notify.save_state({"stamp": now, "summary": {"sampled": now, "channels": {CHANNEL: {"since": boundary - 1,
                                                                                        "schedule": "daily"}}}})
        notify.run_check()
        self.assertEqual(notify.load_state()["summary"]["channels"], {}, "due while standby: starts again")

    def test_archive_pruned_once_a_channel_is_gone_twice(self):
        kept = []
        saved = notify.prune_archive
        notify.prune_archive = kept.append
        notify.interfaces = lambda: {}
        notify.is_carp_backup = lambda config, unknown=True: True
        try:
            notify.run_check()
            self.assertEqual(kept, [], "nothing to compare with yet")
            notify.load_config = lambda: {"general": {"enabled": "1"}, "channels": [], "hostname": "fw"}
            notify.run_check()
            notify.run_check()
        finally:
            notify.prune_archive = saved
        self.assertEqual(kept, [{CHANNEL}, set()], "one read without it keeps its reports")

    def test_no_interfaces_reading_leaves_the_state(self):
        notify.save_state({"stamp": 1, "ids": {"inode": 5, "offset": 99}})
        notify.interfaces = lambda: None
        notify.run_check()
        self.assertEqual(notify.load_state(), {"stamp": 1, "ids": {"inode": 5, "offset": 99}},
                         "stamp stays the last good check, so a long outage still goes stale")

    def test_non_text_titles(self):
        self.assertEqual(notify.message("ids", "warning", None, "")["title"], "ids")
        self.assertEqual(notify.message("ids", "warning", 2019, "")["title"], "2019")

    def test_outside_text_pings_no_one_on_discord(self):
        text = "user @everyone from <@&123> <@456> a@b.example"
        from apprise.plugins.discord import USER_ROLE_DETECTION_RE
        self.assertEqual(USER_ROLE_DETECTION_RE.findall(common.quiet(text)), [], "nothing Apprise's Discord would ping")
        import apprise
        calls, original = [], apprise.Apprise.notify
        apprise.Apprise.notify = lambda this, **kw: calls.append(kw) or True
        try:
            notify.deliver({"uuid": CHANNEL, "url": "discord://1/abc"}, "t", text, "warning")
            notify.deliver({"uuid": CHANNEL, "url": "tgram://123456789:abcdefg_hijklmnop/1"}, "t", text, "warning")
        finally:
            apprise.Apprise.notify = original
        self.assertEqual([c["body"] for c in calls], [common.quiet(text), text], "only for Discord")
    def test_stale_temporary_files_go(self):
        os.makedirs(notify.KEY_DIR)
        for name, age in ((f"{CHANNEL}-template.1.tmp", 7200), (f"{CHANNEL}-template.2.tmp", 10)):
            path = os.path.join(notify.KEY_DIR, name)
            open(path, "w").close()
            os.utime(path, (notify.time.time() - age,) * 2)
        notify.prune_key_files([])
        self.assertEqual(os.listdir(notify.KEY_DIR), [f"{CHANNEL}-template.2.tmp"], "one still being written stays")

    def test_long_outside_text_is_cut(self):
        item = notify.message("syslog", "warning", "t" * 500, "b" * 9000, {"program": "p" * 500})
        self.assertEqual((len(item["title"]), len(item["body"]), len(item["facts"]["program"])),
                         (common.TITLE_MAX, common.BODY_MAX, common.FACT_MAX))
        self.assertTrue(item["body"].endswith("…"))

    def test_a_digest_fits_a_small_service(self):
        found = [dict(notify.message("ids", "warning", f"alert {i}", ""), uuid=CHANNEL) for i in range(137)]
        body = notify.digest(found, 5)[0]["body"].splitlines()
        self.assertEqual((len(body), body[-1]), (notify.DIGEST_LINES + 1, "- and 117 more"))
        found = [dict(notify.message("syslog", "warning", f"{i} " + "x" * 110, ""), uuid=CHANNEL) for i in range(30)]
        body = notify.digest(found, 5)[0]["body"]
        self.assertLess(len(body), 1024, "Pushover's limit")
        self.assertTrue(body.endswith(f"- and {30 - len(body.splitlines()) + 1} more"))

    def test_a_failed_configd_action_is_no_answer(self):
        saved = common.CONFIGCTL
        common.CONFIGCTL = os.path.join(self.folder, "configctl")
        with open(common.CONFIGCTL, "w") as handle:
            handle.write('#!/bin/sh\necho \'{"stale": true}\'\nexit 1\n')
        os.chmod(common.CONFIGCTL, 0o755)
        try:
            self.assertIsNone(common.configctl_json("interface", "gateways", "status"))
        finally:
            common.CONFIGCTL = saved


class Archive(unittest.TestCase):
    UUID = "0e3bfb1c-5c8e-4d1c-9a57-7b1f0c2d3e4f"
    REPORT = {"title": "Daily summary", "host": "fw", "span": "a to b", "sections": [
        {"title": "Events", "head": None, "rows": [["<b>x</b>"]], "graphs": []}]}

    def setUp(self):
        self.folder = tempfile.mkdtemp()
        self.saved = summary.REPORTS_DIR, notify.REPORTS_DIR, notify.load_config
        summary.REPORTS_DIR = notify.REPORTS_DIR = os.path.join(self.folder, "reports")
        notify.load_config = lambda: {"channels": [{"uuid": self.UUID, "description": "Mail"}]}

    def tearDown(self):
        summary.REPORTS_DIR, notify.REPORTS_DIR, notify.load_config = self.saved
        shutil.rmtree(self.folder)

    def test_kept_listed_and_opened(self):
        start = int(notify.time.mktime((2026, 9, 1, 7, 0, 0, 0, 0, -1)))
        for day in range(62):
            summary.archive_report(self.REPORT, self.UUID, "daily", start + day * 86400)
        listed = notify.run_reports()
        self.assertEqual(len(listed), summary.REPORTS_KEEP["daily"], "the oldest beyond the limit go")
        self.assertEqual((listed[0]["channel"], listed[0]["schedule"]), ("Mail", "Daily"))
        newest = notify.time.strftime("%Y%m%d-%H%M%S", notify.time.localtime(start + 61 * 86400))
        self.assertTrue(listed[0]["name"].endswith(f"-{newest}.html"), "newest first")
        page = notify.base64.b64decode(notify.run_report(listed[0]["name"])["payload"]).decode()
        self.assertIn("&lt;b&gt;x&lt;/b&gt;", page)
        self.assertEqual(os.stat(os.path.join(summary.REPORTS_DIR, listed[0]["name"])).st_mode & 0o777, 0o600)
        for second in range(12):
            summary.archive_report(self.REPORT, self.UUID, "daily", start + second, manual=True)
        listed = notify.run_reports()
        self.assertEqual(sum(r["schedule"] == "Daily (so far)" for r in listed), summary.REPORTS_MANUAL)
        self.assertEqual(sum(r["schedule"] == "Daily" for r in listed), summary.REPORTS_KEEP["daily"],
                         "sent by hand, they do not push out scheduled ones")

    def test_only_its_own_names_are_opened(self):
        for name in ("../state.json", "/etc/master.passwd", self.UUID + "-daily-20260927-0700.html/../x", ""):
            self.assertEqual(notify.run_report(name), {"status": "failed"}, name)

    def test_deleted_one_at_a_time(self):
        name = summary.archive_report(self.REPORT, self.UUID, "weekly", 0)
        for bad in ("../state.json", self.UUID + "-weekly-19700101-000000.html/../x", ""):
            self.assertEqual(notify.run_delete(bad), {"status": "failed"}, bad)
        self.assertEqual(notify.run_delete(name), {"status": "ok"})
        self.assertEqual(summary.archived_reports(), [])

    def test_a_deleted_channel_takes_its_reports(self):
        summary.archive_report(self.REPORT, self.UUID, "weekly", 0)
        other = "11111111-2222-3333-4444-555555555555"
        summary.archive_report(self.REPORT, other, "weekly", 60)
        summary.prune_archive({other})
        self.assertEqual([r["channel"] for r in summary.archived_reports()], [other])

    def test_a_failed_summary_by_hand_leaves_no_page(self):
        channel = {"uuid": self.UUID, "description": "Mail", "enabled": "1", "events": [], "summary": "daily",
                   "summaryEvents": [], "summarySections": []}
        saved = notify.load_config, notify.load_state, notify.deliver, notify.interfaces, notify.is_carp_backup
        notify.load_config = lambda: {"general": {"enabled": "1"}, "channels": [channel], "hostname": "fw"}
        notify.load_state = lambda: {"stamp": int(notify.time.time()),
                                     "summary": {"channels": {self.UUID: {"since": 0, "schedule": "daily"}}}}
        notify.deliver = lambda *a: self.delivered.append(a) or (False, "unreachable")
        self.delivered = []
        notify.interfaces = lambda: {}
        notify.is_carp_backup = lambda config, unknown=True: False
        try:
            self.assertEqual(notify.run_summary(self.UUID)["status"], "failed")
            self.assertEqual(len(self.delivered), 1, "delivery was tried")
            self.assertEqual(self.delivered[0][4]["title"], "Daily summary so far", "the page says so too")
            notify.load_state = lambda: {"stamp": int(notify.time.time()) - 900,
                                         "summary": {"channels": {self.UUID: {"since": 0, "schedule": "daily"}}}}
            self.assertIn("Checks have stopped", notify.run_summary(self.UUID)["message"], "stale figures refused")
            notify.load_state = lambda: {"stamp": int(notify.time.time()),
                                         "summary": {"channels": {self.UUID: {"since": 0, "schedule": "daily"}}}}
            notify.deliver = lambda *a: 1 / 0
            self.assertIn("could not be sent", notify.run_summary(self.UUID)["message"])
        finally:
            notify.load_config, notify.load_state, notify.deliver, notify.interfaces, notify.is_carp_backup = saved
        self.assertEqual(summary.archived_reports(), [])

    def test_a_summary_dropped_from_the_queue_takes_its_page(self):
        name = summary.archive_report(self.REPORT, self.UUID, "daily", 0)
        item = dict(notify.message("summary", "info", "Daily summary", "short"), uuid=self.UUID, report=self.REPORT,
                    archive=name)
        notify.send([{"uuid": self.UUID, "events": [], "summary": "none"}], "", [], [item])
        self.assertEqual(summary.archived_reports(), [], "its channel no longer has a summary")
        name = summary.archive_report(self.REPORT, self.UUID, "daily", 0)
        notify.send([], "", [], [dict(item, archive=name)])
        self.assertEqual(summary.archived_reports(), [], "its channel was disabled")

    def test_an_unsent_summary_leaves_the_archive(self):
        channel = {"uuid": self.UUID, "description": "Mail", "events": [], "summary": "daily"}
        item = notify.archived({"general": {}}, dict(notify.message("summary", "info", "Daily summary", "short"),
                                                     uuid=self.UUID, report=self.REPORT), "daily", 0)
        self.assertEqual(len(summary.archived_reports()), 1, "archived as built, for its link")
        saved = notify.deliver
        try:
            notify.deliver = lambda *a: (False, "unreachable")
            notify.send([channel], "", [], [dict(item, time=item["time"] - notify.RETRY_SECONDS - 1)])
        finally:
            notify.deliver = saved
        self.assertEqual(summary.archived_reports(), [], "given up on: never sent")


if __name__ == "__main__":
    unittest.main()
