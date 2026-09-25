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


if __name__ == "__main__":
    unittest.main()
