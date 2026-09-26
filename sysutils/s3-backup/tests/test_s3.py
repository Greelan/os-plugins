"""The S3 provider against a real S3 server (rclone serve s3, over TLS) and a hostile one."""

import fcntl
import http.server
import json
import os
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
HARNESS = os.path.join(HERE, "s3_harness.php")
RCLONE = os.environ.get("RCLONE") or shutil.which("rclone")
CORE = os.environ.get("OPNSENSE_CORE")
SECRET = "s3cr3t/Key+With=Symbols"


def free_port():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


class Hostile(http.server.BaseHTTPRequestHandler):
    """An endpoint that answers like S3 but with a forged log line, an endless listing, too much, or
    odd answers to a delete."""
    mode = ""
    LISTING = (b"<ListBucketResult>" + b"".join(
        b"<Contents><Key>fw/config-172700000%d.xml</Key></Contents>" % i for i in (2, 3, 4)) + b"</ListBucketResult>")

    def answer(self, status, body):
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except OSError:
            pass  # the provider hung up once it had seen enough

    def do_GET(self):
        if self.mode == "error":
            self.answer(403, ("<Error><Code>AccessDenied</Code><Message>one\nFORGED: s3-backup: uploaded evil\n"
                              + "A" * 5000 + "</Message></Error>").encode())
        elif self.mode == "loop":
            self.answer(200, b"<ListBucketResult><IsTruncated>true</IsTruncated>"
                             b"<NextContinuationToken>same</NextContinuationToken></ListBucketResult>")
        elif self.mode == "large":
            self.answer(200, b"<ListBucketResult>" + b"x" * (20 * 1024 * 1024) + b"</ListBucketResult>")
        else:
            self.answer(200, self.LISTING)

    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", 0)))
        if self.mode == "delete-html":
            self.answer(200, b"<html>ok</html>")
        elif self.mode == "delete-501":
            self.answer(501, b"<Error><Code>NotImplemented</Code><Message>no</Message></Error>")
        else:
            self.answer(403, b"<Error><Code>AccessDenied</Code><Message>no</Message></Error>")

    def do_DELETE(self):
        self.answer(204, b"")

    def log_message(self, *args):
        pass


@unittest.skipUnless(RCLONE and CORE and shutil.which("openssl") and shutil.which("php"),
                     "needs rclone, openssl, php and OPNSENSE_CORE")
class S3(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.cert, cls.key = os.path.join(cls.tmp, "cert.pem"), os.path.join(cls.tmp, "key.pem")
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                        "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
                        "-keyout", cls.key, "-out", cls.cert], check=True, capture_output=True)
        os.makedirs(os.path.join(cls.tmp, "data", "bucket"))
        cls.port = free_port()
        cls.server = subprocess.Popen([RCLONE, "serve", "s3", os.path.join(cls.tmp, "data"),
                                       "--auth-key", f"AKIDTEST,{SECRET}", "--addr", f"127.0.0.1:{cls.port}",
                                       "--cert", cls.cert, "--key", cls.key],
                                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(100):
            try:
                socket.create_connection(("127.0.0.1", cls.port), timeout=0.2).close()
                break
            except OSError:
                time.sleep(0.1)

    @classmethod
    def tearDownClass(cls):
        cls.server.terminate()
        cls.server.wait()
        shutil.rmtree(cls.tmp)

    def run_steps(self, steps, trusted=True, **settings):
        """Run the harness; one answer per step."""
        spec = {"settings": dict({"enabled": "1", "endpoint": f"localhost:{self.port}", "region": "us-east-1",
                                  "bucket": "bucket", "prefix": "fw", "accessKey": "AKIDTEST", "secretKey": SECRET,
                                  "password": "pw", "backupcount": "3"}, **settings),
                "steps": steps}
        command = ["php", "-d", "error_reporting=E_ALL", "-d", "display_errors=1"]
        if trusted:
            command += ["-d", f"openssl.cafile={self.cert}", "-d", f"curl.cainfo={self.cert}"]
        answer = subprocess.run(command + [HARNESS, json.dumps(spec)], capture_output=True, text=True,
                                env=dict(os.environ, OPNSENSE_CORE=CORE))
        return [json.loads(line) for line in answer.stdout.splitlines()[:len(steps)]]

    def local(self, *names, contents="<opnsense/>"):
        """Local backups, newest first, as core lists them."""
        paths = [os.path.join(self.tmp, name) for name in names]
        for path in paths:
            with open(path, "w") as handle:
                handle.write(contents)
        return paths

    def test_upload_and_retention(self):
        seeded = ["config-1727000000.xml", "config-1727000000.5.xml", "config-1727000001.25_123456.xml",
                  "unrelated.txt", "sub/config-1.xml"]
        answers = self.run_steps([["put", f"fw1/{name}"] for name in seeded] + [
            ["upload", self.local("config-1727000002.xml")],
            ["upload", self.local("config-1727000002.xml")],
            ["list", "fw1/sub/"],
            ["list", "fw1/"],
        ], prefix="fw1")
        kept = ["config-1727000002.xml", "config-1727000001.25_123456.xml", "config-1727000000.5.xml"]
        self.assertEqual(answers[5], kept, "newest three, by timestamp, whatever core's name form")
        self.assertEqual(answers[6], kept, "nothing new to send")
        self.assertEqual(answers[7], ["config-1.xml"], "another folder's backups are left alone")
        self.assertEqual(sorted(answers[8]), sorted(kept), "the bucket holds only what is kept")

    def test_new_backup_survives_names_from_a_clock_ahead(self):
        answers = self.run_steps([["put", f"fw2/config-199999999{i}.xml"] for i in range(1, 4)] +
                                 [["upload", self.local("config-1727000009.xml")]], prefix="fw2")
        self.assertIn("config-1727000009.xml", answers[-1])

    def test_newest_by_time_not_by_text(self):
        # core lists names sorted as text, so a shorter stamp can come first
        answers = self.run_steps([["upload", self.local("config-20260924.xml", "config-1790337832.0334.xml")]],
                                 prefix="fw4")
        self.assertEqual(answers[0][0], "config-1790337832.0334.xml")

    def test_running_config_not_a_copied_backup(self):
        # an older backup copied in under a newer name is not what runs
        running = self.local("config-1790000000.xml", contents="<opnsense><a/></opnsense>")
        copied = self.local("config-1790000099.xml", contents="<opnsense><b/></opnsense>")
        answers = self.run_steps([["upload", copied + running, running[0]]], prefix="fw5")
        self.assertEqual(answers[0][0], "config-1790000000.xml")

    def test_running_config_without_a_backup(self):
        running = self.local("running.xml",
                             contents="<opnsense><revision><time>1790000123.45</time></revision></opnsense>")
        answers = self.run_steps([["upload", self.local("config-1790000000.xml"), running[0]]], prefix="fw6")
        self.assertEqual(answers[0][0], "config-1790000123.45.xml")

    def test_waits_for_a_save_to_finish(self):
        running = self.local("config-1790000200.xml")
        with open(running[0]) as handle:
            fcntl.flock(handle, fcntl.LOCK_EX)
            threading.Timer(1, fcntl.flock, (handle, fcntl.LOCK_UN)).start()
            answers = self.run_steps([["upload", running]], prefix="fw7")
        self.assertEqual(answers[0][0], "config-1790000200.xml")

    def test_listing_follows_pages(self):
        answers = self.run_steps([["put", f"fw3/config-17000{i}.xml"] for i in range(10000, 11005)] +
                                 [["list", "fw3/"]], prefix="fw3")
        self.assertEqual(len(answers[-1]), 1005)

    def test_wrong_secret_and_untrusted_certificate(self):
        self.assertIn("SignatureDoesNotMatch", self.run_steps([["list", "fw/"]], secretKey="wrong")[0]["error"])
        self.assertIn("Could not reach", self.run_steps([["list", "fw/"]], trusted=False)[0]["error"])

    def test_invalid_settings_stop_before_anything_is_sent(self):
        answers = self.run_steps([["upload", self.local("config-1727000010.xml")], ["list", "fw8/"]],
                                 region="", prefix="fw8")
        self.assertIn("The S3 settings are not valid: region:", answers[0]["error"], "names the setting")
        self.assertEqual(answers[1], [], "nothing sent")
        error = self.run_steps([["upload", self.local("config-1727000011.xml")]], endpoint="localhost:99999")[0]["error"]
        self.assertIn("endpoint: Enter a port from 1 to 65535.", error)
        self.assertEqual(error.count("endpoint"), 1, "one message for the port")

    def test_revision_time_in_any_language(self):
        running = self.local("running-de.xml",
                             contents="<opnsense><revision><time>1790000123,45</time></revision></opnsense>")
        answers = self.run_steps([["upload", self.local("config-1790000000.xml"), running[0]]], prefix="fw9")
        self.assertEqual(answers[0][0], "config-1790000123.45.xml")

    def test_one_save_is_one_backup(self):
        # sent under its revision time (core rounds to two decimals), then found again under core's name
        running = self.local("config-1790000300.4567.xml",
                             contents="<opnsense><revision><time>1790000300.46</time></revision></opnsense>")
        answers = self.run_steps([["put", "fw10/config-1790000300.46.xml"], ["upload", running], ["list", "fw10/"]],
                                 prefix="fw10")
        self.assertEqual(answers[2], ["config-1790000300.46.xml"])
        answers = self.run_steps([["put", "fw15/config-1790000300.46.xml"], ["upload", running], ["list", "fw15/"]],
                                 prefix="fw15", backupcount="0")
        self.assertEqual(answers[2], ["config-1790000300.46.xml"], "with keep-all too")
        # two saves 30 ms apart are two backups
        other = self.local("config-1790000300.49.xml", contents="<opnsense><d/></opnsense>")
        answers = self.run_steps([["put", "fw16/config-1790000300.46.xml"], ["upload", other], ["list", "fw16/"]],
                                 prefix="fw16")
        self.assertEqual(len(answers[2]), 2)

    def test_a_hand_made_copy_is_not_matched(self):
        running = self.local("config-1790000400.xml", contents="<opnsense><c/></opnsense>")
        copy = self.local("config-1790000400.1234_bak.xml", contents="<opnsense><c/></opnsense>")
        answers = self.run_steps([["upload", copy + running, running[0]]], prefix="fw11")
        self.assertEqual(answers[0][0], "config-1790000400.xml")

    def test_names_from_a_clock_ahead_go_first(self):
        answers = self.run_steps([["put", f"fw12/config-199999999{i}.xml"] for i in range(1, 3)] +
                                 [["put", "fw12/config-1727000008.xml"],
                                  ["upload", self.local("config-1727000009.xml")]], prefix="fw12")
        self.assertEqual(answers[-1], ["config-1727000009.xml", "config-1727000008.xml", "config-1999999992.xml"])

    def test_keep_all_asks_for_the_one_backup(self):
        answers = self.run_steps([["upload", self.local("config-1727000020.xml")],
                                  ["upload", self.local("config-1727000020.xml")], ["list", "fw13/"]],
                                 prefix="fw13", backupcount="0")
        self.assertEqual(answers[0], ["config-1727000020.xml"])
        self.assertEqual(answers[1], ["config-1727000020.xml"])
        self.assertEqual(answers[2], ["config-1727000020.xml"], "sent once")

    def test_page_gets_values_and_no_secrets(self):
        fields = self.run_steps([["fields"]], endpoint='"><script>x</script>')[0]
        self.assertEqual(fields["endpoint"], '"><script>x</script>', "the page escapes it")
        # a saved secret is only marked as saved, so its box shows dots
        self.assertEqual((fields["secretKey"], fields["password"], fields["passwordconfirm"]),
                         ("(saved)", "(saved)", "(saved)"))
        empty = self.run_steps([["fields"]], secretKey="", password="")[0]
        self.assertEqual((empty["secretKey"], empty["password"], empty["passwordconfirm"]), ("", "", ""))

    def hostile(self, mode, steps, **settings):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.cert, self.key)
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), type("Handler", (Hostile,), {"mode": mode}))
        server.socket = context.wrap_socket(server.socket, server_side=True)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            return self.run_steps(steps, endpoint=f"localhost:{server.server_port}", **settings)
        finally:
            server.shutdown()
            server.server_close()

    def test_hostile_endpoint(self):
        for mode, expected in (("error", "AccessDenied: one FORGED"), ("loop", "kept returning more"),
                               ("large", "larger answer than S3")):
            error = self.hostile(mode, [["list", "fw/"]])[0]["error"]
            self.assertIn(expected, error, mode)
            self.assertNotIn("\n", error, "one line, whatever the endpoint sends")
            self.assertLess(len(error), 300)

    def test_odd_answers_to_a_delete(self):
        # the listing holds the running backup and two older ones; one is to go
        running = self.local("config-1727000004.xml")
        answer = self.hostile("delete-html", [["upload", running]], backupcount="1")[0]
        self.assertIn("something other than a delete result", answer["error"], "a 2xx that is no DeleteResult fails")
        answer = self.hostile("delete-403", [["upload", running]], backupcount="1")[0]
        self.assertIn("AccessDenied", answer["error"], "a refusal is reported, not worked around")
        answer = self.hostile("delete-501", [["upload", running]], backupcount="1")[0]
        self.assertEqual(answer, ["config-1727000004.xml"], "no DeleteObjects: one DELETE each")


if __name__ == "__main__":
    unittest.main()
