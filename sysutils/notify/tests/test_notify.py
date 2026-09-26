"""Channel URLs: files a service opens come only from the channel, and outside text is escaped."""

import http.server
import json
import os
import shutil
import sys
import tempfile
import threading
import unittest

SCRIPTS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src", "opnsense", "scripts",
                       "OPNsense", "Notify")
sys.path.insert(0, os.path.join(SCRIPTS, "lib"))
sys.path.insert(0, SCRIPTS)

import notify  # noqa: E402

notify.log = lambda *args: None


class Case(unittest.TestCase):
    def setUp(self):
        self.keys = tempfile.mkdtemp()
        notify.KEY_DIR = os.path.join(self.keys, "keys")
        self.channel = {"uuid": "c1", "url": "", "files": {}}
        notify.saved_channel = lambda uuid: self.channel

    def tearDown(self):
        shutil.rmtree(self.keys)

    def build(self, service, **fields):
        """Save the channel as the dialog would, and keep what was stored."""
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as handle:
            json.dump({"uuid": "c1", "service": service, "fields": dict(changed="1", **fields)}, handle)
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

    def test_the_browser_never_gets_them(self):
        self.build("discord", template='{"content": "x"}', **self.WEBHOOK)
        described = notify.describe_url(self.channel["url"])
        self.assertNotIn("template", described["fields"])
        self.assertIn("template", described["saved"])

    def test_written_private_and_pruned(self):
        self.build("discord", template='{"content": "x"}', **self.WEBHOOK)
        path = os.path.join(notify.KEY_DIR, "c1-template")
        url = notify.with_key_files(self.channel)
        self.assertIn(notify.urllib.parse.quote(path, safe=""), url)
        self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
        notify.prune_key_files([{"uuid": "c1", "url": "discord://123/abc"}])
        self.assertFalse(os.path.exists(path))

    def test_old_channels_with_a_path_do_not_send(self):
        ok, error = notify.deliver({"uuid": "c1", "url": "discord://1/a?template=/etc/master.passwd"}, "t", "b", "info")
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
        ok, _ = notify.deliver({"uuid": "c1", "url": url}, "Failed login",
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

    def test_status_below_level_is_not_resolved(self):
        item = {"statusCode": 0, "title": "Firmware", "message": "stale"}
        notify.configctl_json = lambda *args: {"firmware": item}
        state, _ = notify.check_status({"general": {"statusLevel": "warning"}}, None)
        state["checked"] = 0
        state, messages = notify.check_status({"general": {"statusLevel": "error"}}, state)
        self.assertEqual(messages, [])
        notify.configctl_json = lambda *args: {}
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
    PF_RULES = """scrub on vtnet0 all fragment reassemble
  [ Evaluations: 100       Packets: 50        Bytes: 900         States: 0     ]
block drop in log inet all label "02f4bab031b57d1e30553ce08e0ec131"
  [ Evaluations: 1234      Packets: 40        Bytes: 2400        States: 0     ]
  [ Inserted: uid 0 pid 4242 State Creations: 0     ]
block drop in log inet6 all label "02f4bab031b57d1e30553ce08e0ec131"
  [ Evaluations: 1234      Packets: 2         Bytes: 120         States: 0     ]
pass in quick on lo0 all label "0f8a3d1e5b6c4d2e8f9a0b1c2d3e4f5a"
  [ Evaluations: 99        Packets: 999       Bytes: 9999        States: 3     ]
"""

    PATCHED = ("sample_counters", "pf_states", "configctl_json", "ruleset_stamp", "boot_time")

    def setUp(self):
        self.run = notify.subprocess.run
        self.saved = {name: getattr(notify, name) for name in self.PATCHED}

    def tearDown(self):
        notify.subprocess.run = self.run
        for name, value in self.saved.items():
            setattr(notify, name, value)

    def pf(self, output):
        notify.subprocess.run = lambda *args, **kwargs: type("Done", (), {"stdout": output, "returncode": 0})()

    def test_interface_counters(self):
        notify.configctl_json = lambda *args: self.PF_INTERFACES if args == ("filter", "diag", "info",
                                                                             "interfaces") else None
        found, cleared = notify.pf_interfaces()
        self.assertEqual(found["vtnet0"]["in_pass"], [1010, 501000], "IPv4 and IPv6 together")
        self.assertEqual(found["vtnet0"]["in_block"], [25, 1600])
        self.assertEqual(cleared["vtnet0"], "2026-09-24T10:00:00")
        notify.configctl_json = lambda *args: None
        self.assertIsNone(notify.pf_interfaces(), "nothing read is not all zero")
        self.pf("")
        self.assertIsNone(notify.pf_block_rules())

    def test_block_rules_only(self):
        self.pf(self.PF_RULES)
        self.assertEqual(notify.pf_block_rules(), ({"02f4bab031b57d1e30553ce08e0ec131": 42},
                                                   {"02f4bab031b57d1e30553ce08e0ec131": "4242"}))

    def test_reset_counters_count_in_full(self):
        self.assertEqual(notify.counter_growth(None, {"a": 5}), {}, "first sample is the baseline")
        self.assertEqual(notify.counter_growth({"a": 5, "b": 9}, {"a": 8, "b": 3, "c": 4}),
                         {"a": 3, "b": 3}, "a counter not sampled before is a baseline")
        self.assertEqual(notify.counter_growth({}, {"rule x": 7}), {"rule x": 7}, "a rule that started matching")
        self.assertEqual(notify.counter_growth({}, {"rule x": 7}, rules=False), {}, "rules not sampled before")

    def test_rule_reload_resets_rule_counters(self):
        previous, current = {"rule x": 10000, "if a in_block packets": 50}, {"rule x": 12000, "if a in_block packets": 60}
        self.assertEqual(notify.counter_growth(previous, current, reset={"rule x"}),
                         {"rule x": 12000, "if a in_block packets": 10}, "interface counters survive a reload")
        notify.sample_counters = lambda devices, rules: (dict(current), {"x": "2"}, {})
        notify.pf_states = lambda: None
        channel = {"uuid": "c1", "events": [], "summary": "daily", "summarySections": ["firewall"]}
        config = {"general": {}, "interfaces": {"a": "WAN"}}
        now = notify.last_boundary(int(notify.time.time()), "daily", 7, 1) - 60
        previous_state = {"counters": previous, "loads": {"x": "1"}, "rules": True, "ruleset": 1,
                          "channels": {"c1": {"since": now - 30, "schedule": "daily", "totals": {}, "peaks": {}}}}
        notify.ruleset_stamp = lambda: 1
        state, _ = notify.update_summaries(config, [channel], previous_state, [], now)
        self.assertEqual(state["channels"]["c1"]["totals"]["rule x"], 12000, "loaded by another pfctl")
        notify.sample_counters = lambda devices, rules: (dict(current), {"x": "1"}, {})
        state, _ = notify.update_summaries(config, [channel], previous_state, [], now)
        self.assertEqual(state["channels"]["c1"]["totals"]["rule x"], 2000, "rules.debug alone does not reset")
        notify.sample_counters = lambda devices, rules: (dict(current), {"x": "2"}, {})
        state, _ = notify.update_summaries(dict(config, keepCounters=True), [channel], previous_state, [], now)
        self.assertEqual(state["channels"]["c1"]["totals"]["rule x"], 2000, "kept counters only grow")

    def test_failed_and_cleared_readings(self):
        self.assertEqual(notify.counter_growth({"rule x": 1000005}, {"rule x": 800010}, kept=True), {},
                         "kept counters drop only when a label loses rules")
        notify.pf_states = lambda: None
        notify.ruleset_stamp = lambda: 1
        channel = {"uuid": "c1", "events": [], "summary": "daily", "summarySections": ["firewall"]}
        config = {"general": {"summaryHour": "24"}, "interfaces": {"a": "WAN"}}
        now = notify.last_boundary(int(notify.time.time()), "daily", 7, 1) - 1000
        state = {"counters": {"rule x": 5000000, "if a in_block packets": 50}, "loads": {"x": "1"},
                 "cleared": {"a": "T1"}, "rules": True, "ruleset": 1,
                 "channels": {"c1": {"since": now - 30, "schedule": "daily", "totals": {}, "peaks": {}}}}
        notify.sample_counters = lambda devices, rules: ({"if a in_block packets": 55}, None, {"a": "T1"})
        state, _ = notify.update_summaries(config, [channel], state, [], now)
        self.assertEqual(state["channels"]["c1"]["totals"], {"if a in_block packets": 5}, "rules not read")
        notify.sample_counters = lambda devices, rules: ({"rule x": 5000010, "if a in_block packets": 60},
                                                         {"x": "1"}, {"a": "T2"})
        state, _ = notify.update_summaries(config, [channel], state, [], now + 60)
        self.assertEqual(state["channels"]["c1"]["totals"], {"if a in_block packets": 5}, "read at most every 5 minutes")
        state, _ = notify.update_summaries(config, [channel], state, [], now + notify.SAMPLE_SECONDS)
        self.assertEqual(state["channels"]["c1"]["totals"], {"if a in_block packets": 65, "rule x": 10},
                         "a cleared interface starts from zero; the rule carried over grows by 10")

    def test_kept_counters_reset_on_reboot(self):
        notify.pf_states = lambda: None
        notify.ruleset_stamp = lambda: 1
        notify.sample_counters = lambda devices, rules: ({"rule x": 3000}, {"x": "9"}, {})
        channel = {"uuid": "c1", "events": [], "summary": "weekly", "summarySections": ["firewall"]}
        now = notify.last_boundary(int(notify.time.time()), "weekly", 7, 1) + 60
        state = {"counters": {"rule x": 5000000}, "loads": {"x": "1"}, "rules": True, "boot": 100,
                 "channels": {"c1": {"since": now - 30, "schedule": "weekly", "totals": {}, "peaks": {}}}}
        notify.boot_time = lambda: 200
        state, _ = notify.update_summaries({"general": {}, "keepCounters": True, "interfaces": {}}, [channel],
                                           state, [], now)
        self.assertEqual(state["channels"]["c1"]["totals"], {"rule x": 3000})

    def test_new_period_keeps_the_closing_reading(self):
        notify.pf_states = lambda: (900, 1000)
        notify.sample_counters = lambda devices, rules: ({}, {}, {})
        channel = {"uuid": "c1", "events": [], "summary": "daily", "summarySections": ["health"]}
        now = notify.last_boundary(int(notify.time.time()), "daily", 7, 1) + 60
        state = {"channels": {"c1": {"since": now - 86400, "schedule": "daily", "totals": {}, "peaks": {}}}}
        state, due = notify.update_summaries({"general": {}, "interfaces": {}}, [channel], state, [], now)
        self.assertEqual(len(due), 1)
        self.assertEqual(state["channels"]["c1"]["peaks"]["states"], 900)

    def test_monthly_boundaries(self):
        def at(*args):
            return int(notify.datetime.datetime(*args).timestamp())

        def boundary(now, date):
            return notify.datetime.datetime.fromtimestamp(notify.last_boundary(now, "monthly", 7, 1, date))
        self.assertEqual(boundary(at(2026, 3, 15, 12), 31), notify.datetime.datetime(2026, 2, 28, 7))
        self.assertEqual(boundary(at(2026, 3, 31, 8), 31), notify.datetime.datetime(2026, 3, 31, 7))
        self.assertEqual(boundary(at(2026, 1, 10, 12), 15), notify.datetime.datetime(2025, 12, 15, 7))
        self.assertEqual(boundary(at(2028, 2, 29, 6), 31), notify.datetime.datetime(2028, 1, 31, 7))
        self.assertEqual(boundary(at(2028, 3, 1, 6), 31), notify.datetime.datetime(2028, 2, 29, 7))
        self.assertEqual(boundary(at(2026, 5, 1, 6), 30), notify.datetime.datetime(2026, 4, 30, 7))
        self.assertEqual(boundary(at(2026, 3, 1, 6), 30), notify.datetime.datetime(2026, 2, 28, 7),
                         "a day past a short month's end is its last day")

    def test_boundaries(self):
        now = int(notify.datetime.datetime(2026, 9, 26, 6, 30).timestamp())  # a Saturday
        self.assertEqual(notify.datetime.datetime.fromtimestamp(notify.last_boundary(now, "daily", 7, 1)),
                         notify.datetime.datetime(2026, 9, 25, 7, 0))
        self.assertEqual(notify.datetime.datetime.fromtimestamp(notify.last_boundary(now, "weekly", 7, 1)),
                         notify.datetime.datetime(2026, 9, 21, 7, 0))

    def test_period_is_due_once_after_its_hour(self):
        notify.sample_counters = lambda devices, rules: ({"if vtnet0 in_block packets": 10, "if vtnet0 in_pass bytes": 5}, {}, {})
        notify.pf_states = lambda: (100, 1000)
        channel = {"uuid": "c1", "events": [], "summary": "daily", "summaryEvents": ["gateway"],
                   "summarySections": ["firewall", "health"]}
        config = {"general": {"summaryHour": "7"}, "interfaces": {"vtnet0": "WAN"}}
        notify.ruleset_stamp = lambda: 1
        start = int(notify.datetime.datetime(2026, 9, 26, 6, 0).timestamp())
        state, due = notify.update_summaries(config, [channel], None, [], start)
        self.assertEqual(due, [])
        notify.sample_counters = lambda devices, rules: ({"if vtnet0 in_block packets": 25, "if vtnet0 in_pass bytes": 9}, {}, {})
        state, due = notify.update_summaries(config, [channel], state, [], start + 1800)
        self.assertEqual(due, [])
        self.assertEqual(state["channels"]["c1"]["totals"], {"if vtnet0 in_block packets": 15},
                         "traffic is not among the channel's sections")
        found = notify.message("gateway", "failure", "Gateway WAN_GW is down", "")
        state, due = notify.update_summaries(config, [channel], state, [found], start + 3660)
        self.assertEqual(len(due), 1)
        self.assertEqual(due[0][1]["events"], {"gateway": 1}, "found in the check that ends the period")
        self.assertEqual(state["channels"]["c1"]["totals"], {}, "a new period starts")
        _, due = notify.update_summaries(config, [channel], state, [], start + 3720)
        self.assertEqual(due, [])

    def test_summary_events_are_not_sent_as_they_happen(self):
        channel = {"uuid": "c1", "events": ["config"], "summary": "weekly", "summaryEvents": ["gateway"]}
        gateway = notify.message("gateway", "failure", "Gateway WAN_GW is down", "")
        self.assertEqual(notify.subscribed([channel]), {"config", "gateway"})
        self.assertFalse(notify.wants(channel, gateway))
        period = notify.add_events({}, channel, [gateway, notify.message("config", "info", "x", "")])
        self.assertEqual(period["events"], {"gateway": 1})

    def test_report(self):
        notify.configctl_json = lambda *args: [{"id": "02f4", "descr": "Default deny / state violation rule"}] \
            if args == ("filter", "list", "rule_ids") else None
        channel = {"uuid": "c1", "summary": "weekly", "summaryEvents": ["gateway"],
                   "summarySections": ["firewall", "traffic"]}
        now = int(notify.time.time())
        period = {"since": now - 3600, "events": {"gateway": 1},
                  "recent": [{"title": "Gateway WAN_GW is down", "time": now - 60}], "totals": {
            "if vtnet0 in_block packets": 1500, "if vtnet0 in_block bytes": 90000,
            "if vtnet0 in_pass bytes": 2500000, "if vtnet0 out_pass bytes": 300000, "rule 02f4": 1500}}
        config = {"interfaces": {"vtnet0": "WAN"}, "eventLabels": {"gateway": "Gateway status"}}
        item = notify.build_summary(config, channel, period, now)
        self.assertEqual((item["event"], item["uuid"], item["title"]), ("summary", "c1", "Weekly summary"))
        body = item["body"]
        self.assertIn("Gateway status: 1", body)
        self.assertIn("Latest 1 of 1", body)
        self.assertIn("WAN: 1,500 in, 0 out (90.0 kB)", body)
        self.assertIn("Default deny / state violation rule: 1,500 packets", body)
        self.assertIn("WAN: 2.5 MB in, 300.0 kB out", body)


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
        boundary = notify.last_boundary(first, "daily", 1, 1)
        self.assertLessEqual(boundary, first)
        self.assertEqual(notify.last_boundary(first + 3600, "daily", 1, 1), boundary)

    def test_a_queued_summary_goes_only_while_the_channel_has_one(self):
        item = notify.message("summary", "info", "Daily summary", "")
        self.assertTrue(notify.wants({"events": [], "summary": "daily"}, item))
        self.assertFalse(notify.wants({"events": [], "summary": "none"}, item))

    def test_a_period_opened_now_starts_from_a_reading_taken_now(self):
        taken = []
        saved = notify.sample_growth, notify.pf_states
        notify.sample_growth = lambda *args: taken.append(1) or ({}, {"counters": {}})
        notify.pf_states = lambda: None
        try:
            now = 1790000000
            previous = {"counters": {}, "sampled": now - 10, "channels": {}}
            channel = {"uuid": "c1", "summary": "daily", "summarySections": ["traffic"], "events": []}
            notify.update_summaries({"general": {}}, [channel], previous, [], now)
        finally:
            notify.sample_growth, notify.pf_states = saved
        self.assertEqual(taken, [1], "read now, although the last reading was only seconds ago")

    def test_each_graph_is_drawn_once_per_run(self):
        drawn, saved = [], notify.draw_graph
        notify.draw_graph = lambda spec, directory: drawn.append(spec["name"]) or f"/x/{spec['name']}"
        notify.GRAPHS.clear()
        try:
            spec = {"name": "cpu-system.png", "start": 1, "end": 2}
            self.assertEqual(notify.drawn_graph(spec), notify.drawn_graph(dict(spec)))
            notify.drawn_graph(dict(spec, end=3))
        finally:
            notify.draw_graph = saved
            notify.GRAPHS.clear()
        self.assertEqual(drawn, ["cpu-system.png", "cpu-system.png"], "once per period, not per channel")

    FETCH = """                 inblock          outblock          inblock6         outblock6

1727000000: 1.0000000000e+01 2.0000000000e+00 5.0000000000e+00 nan
1727000300: -nan -nan -nan -nan
1727000600: 3.0000000000e+01 4.0000000000e+00 nan 1.0000000000e+00
"""

    def test_fetch_keeps_gaps(self):
        saved = notify.command_output
        notify.command_output = lambda command, timeout=30: self.FETCH
        try:
            rows = notify.rrd_fetch("/x.rrd", 1, 2)
        finally:
            notify.command_output = saved
        self.assertEqual([stamp for stamp, _ in rows], [1727000000, 1727000300, 1727000600])
        self.assertEqual(rows[0][1], {"inblock": 10.0, "outblock": 2.0, "inblock6": 5.0, "outblock6": None})
        self.assertEqual(set(rows[1][1].values()), {None})

    def test_blocked_graph_counts_packets_both_ways(self):
        rrd, calls = tempfile.mkdtemp(), []
        saved = notify.RRD_DIR, notify.command_output
        open(os.path.join(rrd, "wan-packets.rrd"), "w").close()
        notify.RRD_DIR = rrd
        notify.command_output = lambda command, timeout=30: calls.append(command) or self.FETCH
        try:
            graph = notify.draw_graph({"kind": "blocks", "key": "wan", "name": "b.png", "title": "WAN blocked",
                                       "start": 1, "end": 2}, rrd)
            with open(graph["path"], "rb") as handle:
                image = handle.read()
        finally:
            notify.RRD_DIR, notify.command_output = saved
            shutil.rmtree(rrd)
        self.assertEqual(calls[0][1:4], ["fetch", os.path.join(rrd, "wan-packets.rrd"), "AVERAGE"])
        self.assertEqual(image[:8], b"\x89PNG\r\n\x1a\n")
        self.assertEqual(notify.struct.unpack(">II", image[16:24]), notify.GRAPH_SIZE)
        self.assertEqual(graph["caption"], "WAN blocked: In peak 30 packets/s, average 22 packets/s; "
                                           "Out peak 5 packets/s, average 4 packets/s", "IPv4 and IPv6 added")

    def test_rates(self):
        self.assertEqual(notify.rate(950, "bits"), "950 bit/s")
        self.assertEqual(notify.rate(212_400_000, "bits"), "212.4 Mbit/s")
        self.assertEqual(notify.rate(3_120, "states"), "3,120")
        self.assertEqual(notify.rate(12.4, "percent"), "12%")

    def test_day_marks(self):
        first = int(notify.datetime.datetime(2026, 9, 1, 12).timestamp())
        self.assertEqual(len(notify.day_marks(first, first + 3 * 86400)), 3)
        self.assertEqual(len(notify.day_marks(first, first + 30 * 86400)), 4, "Mondays only over a month")


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
        self.draw = notify.draw_graph
        notify.GRAPHS.clear()
        self.calls = []
        apprise.Apprise.notify = lambda this, **kw: self.calls.append(kw) or True

    def tearDown(self):
        self.apprise.Apprise.notify = self.original
        notify.draw_graph = self.draw

    def test_a_late_summary_says_so(self):
        body = notify.summary_html(dict(self.REPORT, delayed="(Delayed: this happened at 07:00.)"), {})
        self.assertIn("<em>(Delayed: this happened at 07:00.)</em>", body)

    def test_escaped_with_graphs_in_their_section(self):
        body = notify.summary_html(self.REPORT, {"cpu-system.png": {"path": "/tmp/x", "caption": "Processor: <peak>"}})
        self.assertIn("Failed login for &lt;b&gt;x&lt;/b&gt;", body)
        self.assertIn('<img src="cid:cpu-system.png"', body)
        self.assertIn("<small>Processor: &lt;peak&gt;</small>", body)
        legend = {"path": "/tmp/x", "caption": "x", "legend": [("In", "#4e79a7", "peak 2 bit/s, average 1 bit/s"),
                                                               ("Out", "#e15759", "peak <1>, average 0")]}
        body = notify.summary_html(self.REPORT, {"cpu-system.png": legend})
        self.assertIn('<span style="color:#4e79a7">&#9632;</span> In peak 2 bit/s', body)
        self.assertIn('<span style="color:#e15759">&#9632;</span> Out peak &lt;1&gt;', body)
        self.assertNotIn("cid:", notify.summary_html(self.REPORT, {}), "a graph not drawn is left out")

    def test_html_only_for_email(self):
        notify.draw_graph = lambda spec, directory: None
        notify.deliver({"uuid": "c1", "url": "mailto://127.0.0.1?from=a@example.com&to=b@example.com"},
                       "t", "text", "info", self.REPORT)
        notify.deliver({"uuid": "c1", "url": "tgram://123456789:abcdefg_hijklmnop/1"}, "t", "text", "info", self.REPORT)
        notify.deliver({"uuid": "c1", "url": "mailto://127.0.0.1?from=a@example.com&to=b@example.com&format=text"},
                       "t", "text", "info", self.REPORT)
        self.assertEqual([c["body_format"] for c in self.calls],
                         [self.apprise.NotifyFormat.HTML, self.apprise.NotifyFormat.TEXT, self.apprise.NotifyFormat.TEXT])
        self.assertEqual(self.calls[1]["body"], "text", "Telegram takes HTML, but only a few tags")


class Delivery(unittest.TestCase):
    def test_queued_digest_follows_the_subscription(self):
        found = [notify.message("gateway", "failure", "a", ""), notify.message("ids", "warning", "b", "")]
        item = notify.digest([dict(m, uuid="c1") for m in found], 2)[0]
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
        notify.ifconfig.cache_clear()

    def test_only_a_command_that_succeeded_counts(self):
        self.assertEqual(notify.command_output(["/bin/sh", "-c", "echo ok"]), "ok\n")
        self.assertIsNone(notify.command_output(["/bin/sh", "-c", "echo partial; exit 1"]))
        self.assertEqual(notify.command_output(["/bin/sh", "-c", "echo partial; exit 1"], partial=True), "partial\n")
        self.assertIsNone(notify.command_output(["/nonexistent"]))

    def test_no_ifconfig_reading_is_not_no_interfaces(self):
        saved = notify.command_output
        notify.command_output = lambda command, timeout=30, partial=False: None
        notify.ifconfig.cache_clear()
        try:
            self.assertTrue(notify.is_carp_backup({"general": {"carpMasterOnly": "1"}}), "quiet when it cannot tell")
            self.assertFalse(notify.is_carp_backup({"general": {}}))
        finally:
            notify.command_output = saved

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


if __name__ == "__main__":
    unittest.main()
