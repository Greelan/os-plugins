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
    """An endpoint that answers like S3 but with a forged log line, an endless listing, or too much."""
    mode = ""

    def do_GET(self):
        if self.mode == "error":
            body = ("<Error><Code>AccessDenied</Code><Message>one\nFORGED: s3-backup: uploaded evil\n"
                    + "A" * 5000 + "</Message></Error>").encode()
            self.send_response(403)
        elif self.mode == "loop":
            body = (b"<ListBucketResult><IsTruncated>true</IsTruncated>"
                    b"<NextContinuationToken>same</NextContinuationToken></ListBucketResult>")
            self.send_response(200)
        else:
            body = b"<ListBucketResult>" + b"x" * (20 * 1024 * 1024) + b"</ListBucketResult>"
            self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except OSError:
            pass  # the provider hung up once it had seen enough

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

    def run_steps(self, steps, trusted=True, invalid=None, **settings):
        """Run the harness; one answer per step."""
        spec = {"settings": dict({"endpoint": f"localhost:{self.port}", "region": "us-east-1", "bucket": "bucket",
                                  "prefix": "fw", "accessKey": "AKIDTEST", "secretKey": SECRET, "password": "pw",
                                  "backupcount": "3"}, **settings),
                "steps": steps, "invalid": invalid or []}
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
        answer = self.run_steps([["upload", self.local("config-1727000010.xml")]], invalid=["Enter a host name."])
        self.assertIn("The S3 settings are not valid", answer[0]["error"])

    def test_page_gets_escaped_values_and_no_secrets(self):
        fields = self.run_steps([["fields"]], endpoint='"><script>x</script>')[0]
        self.assertEqual(fields["endpoint"], "&quot;&gt;&lt;script&gt;x&lt;/script&gt;")
        # a saved secret is only marked as saved, so its box shows dots
        self.assertEqual((fields["secretKey"], fields["password"], fields["passwordconfirm"]),
                         ("(saved)", "(saved)", "(saved)"))
        empty = self.run_steps([["fields"]], secretKey="", password="")[0]
        self.assertEqual((empty["secretKey"], empty["password"], empty["passwordconfirm"]), ("", "", ""))

    def test_hostile_endpoint(self):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.cert, self.key)
        for mode, expected in (("error", "AccessDenied: one FORGED"), ("loop", "kept returning more"),
                               ("large", "larger answer than S3")):
            handler = type("Handler", (Hostile,), {"mode": mode})
            server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
            server.socket = context.wrap_socket(server.socket, server_side=True)
            threading.Thread(target=server.serve_forever, daemon=True).start()
            try:
                error = self.run_steps([["list", "fw/"]], endpoint=f"localhost:{server.server_port}")[0]["error"]
            finally:
                server.shutdown()
                server.server_close()
            self.assertIn(expected, error, mode)
            self.assertNotIn("\n", error, "one line, whatever the endpoint sends")
            self.assertLess(len(error), 300)


if __name__ == "__main__":
    unittest.main()
