"""The S3 provider against a real S3 server (rclone serve s3, over TLS) and a hostile one."""

import fcntl
import http.server
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import unittest
import sys
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
HARNESS = os.path.join(HERE, "s3_harness.php")
RCLONE = os.environ.get("RCLONE") or shutil.which("rclone") or ""
CORE = os.environ.get("OPNSENSE_CORE", "")
SECRET = "s3cr3t/Key+With=Symbols"
DOTS = "\ue000" * 8  # what the page shows for a saved secret
AHEAD = int(time.time()) + 365 * 86400  # names from a clock that ran a year ahead
LIMITS = """import os, resource, sys
args, flags = sys.argv[1:], set()
while args[:1] in (["-v"], ["-f"]):
    flags.add(args[0])
    if args[0] == "-f":
        size = int(args[1][:-1]) << {"k": 10, "m": 20, "g": 30}[args[1][-1]]
        resource.setrlimit(resource.RLIMIT_FSIZE, (size, size))
    args = args[2:]
if "-v" not in flags:
    sys.exit(99)
os.execv(args[0], args)
"""


def free_port():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


class Hostile(http.server.BaseHTTPRequestHandler):
    """An endpoint that answers like S3 but with a forged log line, an endless listing, too much, or
    odd answers; it keeps what it was asked, what was put and as what type, and what was deleted."""
    mode = ""
    seen: list = []
    types: list = []
    stored: list = []
    deleted: list = []
    OLD = [f"fw/config-172700000{i}.xml" for i in (2, 3, 4)]

    @staticmethod
    def listing(keys):
        return ("<ListBucketResult>%s</ListBucketResult>" % "".join(
            f"<Contents><Key>{key}</Key></Contents>" for key in keys)).encode()

    def answer(self, status, body, headers=()):
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        for header in headers:
            self.send_header(*header)
        self.end_headers()
        try:
            self.wfile.write(body)
        except OSError:
            pass  # the provider hung up once it had seen enough

    def do_GET(self):
        self.seen.append(("GET", self.path))
        marker = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query).get("marker", ["fw/config-1727000000.xml"])[0]
        number = int(re.findall(r"-([0-9]+)", marker)[0])
        if self.mode in ("endless", "many", "long", "others", "odd"):
            # endless: one key a page, never the last page; many: far more keys than a backup folder holds;
            # long: backup names long enough to fill rclone's output; others: as many long names of other files;
            # odd: endless names outside the folder, which rclone logs one by one
            size, total = {"endless": (1, 0), "many": (1000, 120000), "long": (1000, 60000), "others": (1000, 60000),
                           "odd": (1000, 0)}[self.mode]
            name = {"long": "fw/config-{}." + "0" * 200 + ".xml", "others": "fw/" + "x" * 200 + "-{}",
                    "odd": "other/" + "x" * 200 + "-{}"}.get(self.mode, "fw/config-{}.xml")
            keys = [name.format(n) for n in range(number + 1, number + 1 + size)]
            last = total and number + size >= 1727000000 + total
            self.answer(200, ("<ListBucketResult><IsTruncated>%s</IsTruncated><NextMarker>%s</NextMarker>%s"
                              "</ListBucketResult>" % ("false" if last else "true", keys[-1], "".join(
                                  f"<Contents><Key>{key}</Key><Size>0</Size></Contents>" for key in keys))).encode())
        elif self.mode == "error":
            self.answer(403, (f"<Error><Code>AccessDenied</Code><Message>one\nFORGED: s3-backup: uploaded evil\n"
                              f"{'A' * 5000}</Message></Error>").encode())
        elif self.mode == "huge-error":
            self.answer(403, b"<Error><Code>AccessDenied</Code><Message>" + b"A" * (100 << 20) + b"</Message></Error>")
        elif self.mode == "loop":
            self.answer(200, b"<ListBucketResult><IsTruncated>true</IsTruncated>"
                             b"<NextContinuationToken>same</NextContinuationToken></ListBucketResult>")
        elif self.mode == "large":
            self.answer(200, b"<ListBucketResult>" + b"x" * (20 * 1024 * 1024) + b"</ListBucketResult>")
        elif self.mode == "busy":
            self.answer(503, b"<Error><Code>SlowDown</Code><Message>busy</Message></Error>")
        elif self.mode == "catch-all":
            # e.g. a login page in front of the service
            self.answer(200, b"<html>Sign in</html>")
        elif self.mode == "404":
            # e.g. a web site
            self.answer(404, b"<html>Not Found</html>")
        else:
            # list-once: only the first listing is answered
            if self.mode == "list-once" and [method for method, path in self.seen].count("GET") > 1:
                self.answer(403, b"<Error><Code>AccessDenied</Code><Message>no</Message></Error>")
                return
            keys = self.OLD + self.stored
            self.answer(200, self.listing([key for key in keys if key not in self.deleted]))

    def do_DELETE(self):
        self.seen.append(("DELETE", self.path))
        key = self.path.split("?")[0][len("/bucket/"):]
        if self.mode == "delete-403" and key == "fw/config-1727000002.xml":
            self.answer(403, b"<Error><Code>AccessDenied</Code><Message>no</Message></Error>")
        elif self.mode == "delete-200":
            # e.g. a proxy that blocks deletes
            self.answer(200, b"<html>blocked</html>")
        elif self.mode == "delete-404":
            # e.g. GCS, for what another run removed first
            self.deleted.append(key)
            self.answer(404, b"<Error><Code>NoSuchKey</Code><Message>gone</Message></Error>")
        else:
            self.deleted.append(key)
            self.answer(204, b"")

    def do_HEAD(self):
        self.seen.append(("HEAD", self.path))
        self.answer(404, b"")

    def do_PUT(self):
        self.seen.append(("PUT", self.path))
        self.types.append(self.headers.get("Content-Type"))
        self.rfile.read(int(self.headers.get("Content-Length", 0)))
        if self.mode == "put-403":
            self.answer(403, b"<Error><Code>AccessDenied</Code><Message>no</Message></Error>")
            return
        self.stored.append(self.path.split("?")[0][len("/bucket/"):])
        # kms: an ETag that is not the MD5 of what was sent, as under KMS encryption
        self.answer(200, b"", [("ETag", '"' + "0" * 32 + '"')] if self.mode == "kms" else [])

    def log_message(self, *args):
        pass


@unittest.skipUnless(RCLONE and CORE and shutil.which("openssl") and shutil.which("php"),
                     "needs rclone, openssl, php and OPNSENSE_CORE")
class S3(unittest.TestCase):
    tmp: str
    temp: str
    cert: str
    key: str
    wrapper: str
    call_log: str
    timeout: str
    limits: str
    server: subprocess.Popen
    port: int
    seen: list
    types: list

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        # the harness's and the provider's temporary files, gone with the test's
        cls.temp = os.path.join(cls.tmp, "temp")
        os.makedirs(cls.temp)
        cls.cert, cls.key = os.path.join(cls.tmp, "cert.pem"), os.path.join(cls.tmp, "key.pem")
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                        "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
                        "-keyout", cls.key, "-out", cls.cert], check=True, capture_output=True)
        os.makedirs(os.path.join(cls.tmp, "data", "bucket"))
        # what the provider runs as rclone: the real one, each call's arguments logged
        cls.wrapper, cls.call_log = os.path.join(cls.tmp, "rclone"), os.path.join(cls.tmp, "rclone-calls.log")
        with open(cls.wrapper, "w") as handle:
            handle.write('#!/bin/sh\nprintf \'%s\\n\' "$*" >> "$S3_RCLONE_LOG"\nexec "$RCLONE" "$@"\n')
        os.chmod(cls.wrapper, 0o755)
        # timeout(1), else a perl stand-in that also exits 124
        cls.timeout = shutil.which("timeout") or shutil.which("gtimeout") or os.path.join(cls.tmp, "timeout")
        if cls.timeout == os.path.join(cls.tmp, "timeout"):
            with open(cls.timeout, "w") as handle:
                handle.write('#!/bin/sh\n[ "$1" = -k ] && shift 2\nexec perl -e \''
                             'my $s = shift; my $pid = fork; if (!$pid) { exec @ARGV or die "$ARGV[0]: $!\\n" }'
                             ' $SIG{ALRM} = sub { kill "KILL", $pid; waitpid $pid, 0; exit 124 }; alarm $s;'
                             ' waitpid $pid, 0; exit($? & 127 ? 128 + ($? & 127) : $? >> 8)\' "$@"\n')
            os.chmod(cls.timeout, 0o755)
        # limits(1): the file size limit is applied, the memory one only required
        cls.limits = os.path.join(cls.tmp, "limits")
        with open(cls.limits, "w") as handle:
            handle.write(f"#!{sys.executable}\n" + LIMITS)
        os.chmod(cls.limits, 0o755)
        cls.server, cls.port = cls.serve(os.path.join(cls.tmp, "data"), SECRET)

    @classmethod
    def serve(cls, data, secret):
        """rclone serve s3 over TLS for data, its buckets the directories in it."""
        port = free_port()
        server = subprocess.Popen([RCLONE, "serve", "s3", data, "--auth-key", f"AKIDTEST,{secret}", "--addr",
                                   f"127.0.0.1:{port}", "--cert", cls.cert, "--key", cls.key],
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(100):
            try:
                socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
                break
            except OSError:
                time.sleep(0.1)
        return server, port

    @classmethod
    def tearDownClass(cls):
        cls.server.terminate()
        cls.server.wait()
        shutil.rmtree(cls.tmp)

    def settings(self, **values):
        """Working settings, with values in place of some."""
        return dict({"enabled": "1", "endpoint": f"localhost:{self.port}", "region": "us-east-1", "bucket": "bucket",
                     "prefix": "fw", "accessKey": "AKIDTEST", "secretKey": SECRET, "password": "pw",
                     "backupcount": "3"}, **values)

    def run_steps(self, steps, trusted=True, env=None, config=None, memory="-1", **settings):
        """Run the harness, over config.xml when given; one answer per step."""
        spec = {"settings": self.settings(**settings), "steps": steps}
        if config:
            spec["config"] = config
        command = ["php", "-d", "error_reporting=E_ALL", "-d", "display_errors=1", "-d", f"memory_limit={memory}"]
        environ = dict(os.environ, OPNSENSE_CORE=CORE, RCLONE=os.path.abspath(RCLONE), S3_RCLONE=self.wrapper,
                       S3_RCLONE_LOG=self.call_log, S3_TIMEOUT=self.timeout, S3_LIMITS=self.limits, TMPDIR=self.temp)
        if trusted:
            environ["S3_CA"] = self.cert
        environ.update(env or {})
        answer = subprocess.run(command + [HARNESS, json.dumps(spec)], capture_output=True, text=True, env=environ)
        return [json.loads(line) for line in answer.stdout.splitlines()[:len(steps)]]

    def seed(self, prefix, names):
        """Objects in the bucket under prefix, written through the S3 server as another writer would."""
        source = tempfile.mkdtemp(dir=self.tmp)
        for name in names:
            path = os.path.join(source, name)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            open(path, "w").close()
        env = dict(os.environ, RCLONE_CONFIG_SEED_TYPE="s3", RCLONE_CONFIG_SEED_PROVIDER="Other",
                   RCLONE_CONFIG_SEED_ENDPOINT=f"https://localhost:{self.port}", RCLONE_CONFIG_SEED_REGION="us-east-1",
                   RCLONE_CONFIG_SEED_ACCESS_KEY_ID="AKIDTEST", RCLONE_CONFIG_SEED_SECRET_ACCESS_KEY=SECRET)
        subprocess.run([RCLONE, "--config", os.path.join(self.tmp, "seed.conf"), "--ca-cert", self.cert, "copy", source,
                        f"seed:bucket/{prefix}"], check=True, capture_output=True, env=env)

    def calls(self):
        """The rclone calls since the last look, one argument line each."""
        try:
            with open(self.call_log) as log:
                lines = log.read().splitlines()
        except FileNotFoundError:
            return []
        os.remove(self.call_log)
        return lines

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
        self.seed("fw1", seeded)
        answers = self.run_steps([
            ["upload", self.local("config-1727000002.xml")],
            ["upload", self.local("config-1727000002.xml")],
            ["list", "fw1/sub/"],
            ["list", "fw1/"],
        ], prefix="fw1")
        kept = ["config-1727000002.xml", "config-1727000001.25_123456.xml", "config-1727000000.5.xml"]
        self.assertEqual(answers[0], kept, "newest three, by timestamp, whatever core's name form")
        self.assertEqual(answers[1], kept, "nothing new to send")
        self.assertEqual(answers[2], ["config-1.xml"], "another folder's backups are left alone")
        self.assertEqual(sorted(answers[3]), sorted(kept), "the bucket holds only what is kept")

    def test_new_backup_survives_names_from_a_clock_ahead(self):
        self.seed("fw2", [f"config-{AHEAD + i}.xml" for i in range(1, 4)])
        answers = self.run_steps([["upload", self.local("config-1727000009.xml")]], prefix="fw2")
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
        self.seed("fw3", [f"config-17000{i}.xml" for i in range(10000, 11005)])
        answers = self.run_steps([["list", "fw3/"]], prefix="fw3")
        self.assertEqual(len(answers[-1]), 1005)

    def test_wrong_secret_and_untrusted_certificate(self):
        error = self.run_steps([["list", "fw/"]], secretKey="wrong")[0]["error"]
        self.assertTrue(error.startswith("rclone: error listing: ") and "SignatureDoesNotMatch" in error, error)
        error = self.run_steps([["list", "fw/"]], trusted=False)[0]["error"]
        self.assertTrue(error.startswith("rclone: ") and "certificate" in error, error)

    def test_invalid_settings_stop_before_anything_is_sent(self):
        error = self.run_steps([["upload", self.local("config-1727000010.xml")]], region="", prefix="fw8")[0]["error"]
        self.assertIn("The S3 settings are not valid: region:", error, "names the setting")
        self.assertEqual(self.run_steps([["list", "fw8/"]], prefix="fw8")[0], [], "nothing sent")
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
        self.seed("fw10", ["config-1790000300.46.xml"])
        answers = self.run_steps([["upload", running], ["list", "fw10/"]], prefix="fw10")
        self.assertEqual(answers[1], ["config-1790000300.46.xml"])
        self.seed("fw15", ["config-1790000300.46.xml"])
        answers = self.run_steps([["upload", running], ["list", "fw15/"]], prefix="fw15", backupcount="0")
        self.assertEqual(answers[1], ["config-1790000300.46.xml"], "with keep-all too")
        # two saves 30 ms apart are two backups
        other = self.local("config-1790000300.49.xml", contents="<opnsense><d/></opnsense>")
        self.seed("fw16", ["config-1790000300.46.xml"])
        answers = self.run_steps([["upload", other], ["list", "fw16/"]], prefix="fw16")
        self.assertEqual(len(answers[1]), 2)

    def test_a_hand_made_copy_is_not_matched(self):
        running = self.local("config-1790000400.xml", contents="<opnsense><c/></opnsense>")
        copy = self.local("config-1790000400.1234_bak.xml", contents="<opnsense><c/></opnsense>")
        answers = self.run_steps([["upload", copy + running, running[0]]], prefix="fw11")
        self.assertEqual(answers[0][0], "config-1790000400.xml")

    def test_names_from_a_clock_ahead_go_first(self):
        self.seed("fw12", [f"config-{AHEAD + i}.xml" for i in range(1, 3)] + ["config-1727000008.xml"])
        answers = self.run_steps([["upload", self.local("config-1727000009.xml")]], prefix="fw12")
        self.assertEqual(answers[-1], ["config-1727000009.xml", "config-1727000008.xml", f"config-{AHEAD + 2}.xml"])

    def test_keep_all_looks_only_around_that_second(self):
        self.calls()
        answers = self.run_steps([["upload", self.local("config-1727000020.xml")],
                                  ["upload", self.local("config-1727000020.xml")], ["list", "fw13/"]],
                                 prefix="fw13", backupcount="0")
        self.assertEqual(answers[0], ["config-1727000020.xml"])
        self.assertEqual(answers[1], ["config-1727000020.xml"])
        self.assertEqual(answers[2], ["config-1727000020.xml"], "sent once")
        self.assertTrue([c for c in self.calls() if "--include config-1727000020*" in c], "asked only around that second")

    def test_keep_all_finds_the_same_save_across_a_second(self):
        self.seed("fw20", ["config-1727000019.995.xml"])
        answers = self.run_steps([["upload", self.local("config-1727000020.003.xml")], ["list", "fw20/"]],
                                 prefix="fw20", backupcount="0")
        self.assertEqual(answers[1], ["config-1727000019.995.xml"])

    def test_page_gets_values_and_no_secrets(self):
        # core escapes them (legacy_html_escape_form_data), so they come back as stored
        fields = self.run_steps([["fields"]], endpoint='"><script>x</script>', backupcount="'<b>")[0]
        self.assertEqual(fields["endpoint"]["value"], '"><script>x</script>')
        self.assertEqual(fields["backupcount"]["value"], "'<b>")
        empty = self.run_steps([["fields"]], secretKey="", password="")[0]
        for name in ("secretKey", "password", "passwordconfirm"):
            # a saved secret is only marked as saved, so its box shows dots
            self.assertEqual((fields[name]["value"], empty[name]["value"]), (DOTS, ""), name)

    def test_setup_keeps_saved_secrets_and_names_the_setting(self):
        page = self.setup_page()
        dots = dict(page, secretKey=DOTS, password=DOTS, passwordconfirm=DOTS)
        old = dict(page, secretKey="(saved)", password="(saved)", passwordconfirm="(saved)")
        # typed with the cursor among the dots, or after them
        typed = dict(page, password=DOTS[:3] + "new" + DOTS[3:], passwordconfirm=DOTS + "new")
        answers = self.run_steps([["setup", dots], ["setup", old], ["setup", page], ["setup", typed],
                                  ["setup", dict(page, region="", backupcount="abc")]])
        self.assertEqual(answers[0], {"messages": [], "secretKey": SECRET, "password": "pw", "provider": "Other"},
                         "the dots keep them")
        self.assertEqual(answers[1], answers[0], "so does a page from 1.0, which shows them as (saved)")
        self.assertEqual(answers[2], answers[0], "and empty boxes")
        self.assertEqual(answers[3], {"messages": [], "secretKey": SECRET, "password": "new", "provider": "Other"},
                         "only what is typed")
        self.assertEqual(answers[4]["messages"], [
            "Region: A value is required.",
            "Backup Count: Enter how many backups to keep, up to 1000, or 0 to keep them all.",
        ], "each named, once")

    def test_provider_defaults_to_other(self):
        fields = self.run_steps([["fields"]])[0]
        self.assertEqual(fields["provider"]["value"], "Other")
        self.assertIn('<a href="https://rclone.org/s3/#s3-provider" target="_blank">The names rclone knows</a>',
                      fields["provider"]["help"])
        names = list(fields)
        self.assertEqual(names[names.index("endpoint") + 1], "provider", "the provider follows the endpoint")

    def test_provider_is_a_list_where_the_page_has_one(self):
        # core's page from 26.7.9 on renders a dropdown (opnsense/core#11170)
        new = {"S3_PAGE": os.path.join(CORE, "src", "www", "diag_backup.php")}
        field = self.run_steps([["fields"]], env=new)[0]["provider"]
        self.assertEqual((field["type"], field["value"]), ("dropdown", "Other"))
        self.assertEqual(field["options"]["AWS"], "Amazon Web Services (AWS) S3")
        self.assertIn('For one not listed, choose "Any other S3 compatible provider".', field["help"])
        # a stored name rclone does not list stays selected, first
        field = self.run_steps([["fields"]], env=new, provider="Gone")[0]["provider"]
        self.assertEqual((field["value"], list(field["options"])[0]), ("Gone", "Gone"))
        # without rclone the name can still be read and typed
        field = self.run_steps([["fields"]], env=dict(new, S3_RCLONE="/nonexistent"))[0]["provider"]
        self.assertEqual((field["type"], field["value"]), ("text", "Other"))
        # the page shows help as it is
        listing = os.path.join(self.tmp, "listing")
        with open(listing, "w") as handle:
            handle.write("#!/bin/sh\necho '%s'\n" % json.dumps([{"Name": "s3", "Options": [
                {"Name": "provider", "Examples": [{"Value": "Other", "Help": "<b>&\""}]}]}]))
        os.chmod(listing, 0o755)
        text = self.run_steps([["fields"]], env=dict(new, S3_RCLONE=listing))[0]["provider"]["help"]
        self.assertIn('choose "&lt;b&gt;&amp;&quot;".', text)

    def test_a_save_lists_the_providers_once(self):
        # core's page reads the fields, then saves, with one handle
        self.calls()
        self.run_steps([["fields"], ["setup", self.setup_page()]],
                       env={"S3_PAGE": os.path.join(CORE, "src", "www", "diag_backup.php")})
        self.assertEqual(len([c for c in self.calls() if "config providers" in c]), 1)

    def test_provider_is_a_text_box_on_older_pages(self):
        # 26.7.8 and before, and Business Edition until based on 26.7.9: no box for a type they do not know
        old = os.path.join(self.tmp, "diag_backup.php")
        with open(old, "w") as handle:
            handle.write("<?php if ($field['type'] == 'textarea'): ?><?php endif ?>\n")
        self.calls()
        field = self.run_steps([["fields"]], env={"S3_PAGE": old})[0]["provider"]
        self.assertEqual((field["type"], field["value"]), ("text", "Other"))
        self.assertEqual(self.calls(), [], "rclone is not asked for the list")

    def setup_page(self, **values):
        return self.settings(**dict({"provider": "Other", "secretKey": "", "password": "", "passwordconfirm": ""},
                                    **values))

    def test_bad_provider_name_is_refused(self):
        messages = self.run_steps([["setup", self.setup_page(provider="Bad Name!")]])[0]["messages"]
        self.assertTrue([m for m in messages if m.startswith("Provider: Enter rclone's name")], messages)

    def test_control_characters_in_secrets_are_refused(self):
        # config.xml would drop them, so the next backups would be encrypted with another password
        answer = self.run_steps([["setup", self.setup_page(secretKey="a\x01b", password="a\uffffb",
                                                           passwordconfirm="a\uffffb")]])[0]
        self.assertEqual(answer["messages"], ["Secret access key: Enter the secret access key without control characters.",
                                              "Encrypt Password: Enter a password without control characters."])
        # what config.xml keeps, as 1.1 took it
        answer = self.run_steps([["setup", self.setup_page(secretKey="a\tb\x7f", password="a\tb\x7f",
                                                           passwordconfirm="a\tb\x7f")]])[0]
        self.assertEqual((answer["messages"], answer["secretKey"], answer["password"]), ([], "a\tb\x7f", "a\tb\x7f"))
        # core encrypts with the password's first line only
        answer = self.run_steps([["setup", self.setup_page(password="a\nb", passwordconfirm="a\nb")]])[0]
        self.assertEqual(answer["messages"], ["Encrypt Password: Enter a password without line breaks."])

    def test_unknown_provider_is_refused(self):
        messages = self.run_steps([["setup", self.setup_page(provider="Nope")]])[0]["messages"]
        self.assertIn("Provider: rclone knows no S3 provider named Nope.", messages)

    def test_provider_stored_as_rclone_spells_it(self):
        answer = self.run_steps([["setup", self.setup_page(provider="cloudflare")]])[0]
        self.assertEqual((answer["messages"], answer["provider"]), ([], "Cloudflare"))

    def test_rclone_missing_is_said(self):
        messages = self.run_steps([["setup", self.setup_page()]], env={"S3_RCLONE": "/nonexistent"})[0]["messages"]
        # the rest is what the shell or timeout(1) says, which differs between systems
        self.assertEqual(len(messages), 1, messages)
        self.assertTrue(messages[0].startswith("rclone: "), messages)

    def test_no_secret_on_a_command_line(self):
        password = "Unmistakable-Passw0rd"
        self.calls()
        self.run_steps([["list", "fw17/"], ["upload", self.local("config-1727000030.xml")]], prefix="fw17",
                       password=password)
        calls = self.calls()
        self.assertTrue(calls, "rclone ran")
        for line in calls:
            self.assertNotIn(SECRET, line)
            self.assertNotIn(password, line)

    def test_settings_reach_rclone_as_typed(self):
        # a config file trims spaces, unwraps quotes and expands %(name)s
        os.makedirs(os.path.join(self.tmp, "exact", "bucket"), exist_ok=True)
        for secret in ("`s3cr3t' x\"", "pa%(type)s55"):
            server, port = self.serve(os.path.join(self.tmp, "exact"), secret)
            try:
                answer = self.run_steps([["list", "fw/"]], endpoint=f"localhost:{port}", secretKey=secret)[0]
                self.assertEqual(answer, [], secret)
            finally:
                server.terminate()
                server.wait()

    def test_inherited_rclone_variables_are_ignored(self):
        env = {"RCLONE_CONFIG_S3_ENDPOINT": "https://127.0.0.1:9", "RCLONE_DRY_RUN": "true"}
        answers = self.run_steps([["upload", self.local("config-1727000050.xml")], ["list", "fw19/"]], env=env,
                                 prefix="fw19")
        self.assertEqual(answers[1], ["config-1727000050.xml"])

    def test_missing_bucket_is_said(self):
        error = self.run_steps([["list", "fw/"]], bucket="nobucket")[0]["error"]
        self.assertEqual(error, "The endpoint has no bucket nobucket.")

    def test_an_unknown_provider_fails_when_run(self):
        # e.g. from a restored config.xml; rclone itself would run it as Other
        error = self.run_steps([["list", "fw/"]], provider="Nope")[0]["error"]
        self.assertEqual(error, "rclone knows no S3 provider named Nope.")

    def test_rclone_s_fatal_errors_are_said(self):
        error = self.run_steps([["list", "fw/"]], accessKey="")[0]["error"]
        self.assertTrue(error.startswith("rclone: Failed to create file system"), error)

    def test_a_page_from_before_the_provider_keeps_it(self):
        # a page drawn by 1.1 has no provider box, so core posts null for it
        answer = self.run_steps([["setup", self.setup_page(provider=None)]], provider="Cloudflare")[0]
        self.assertEqual((answer["messages"], answer["provider"]), ([], "Cloudflare"))

    def test_an_empty_provider_is_refused(self):
        messages = self.run_steps([["setup", self.setup_page(provider="")]], provider="Cloudflare")[0]["messages"]
        self.assertEqual(messages, ["Provider: A value is required."])

    def test_gcs_gets_its_provider_on_upgrade(self):
        # rclone signs a header GCS changes unless told it is GCS; 1.1 had no provider setting
        for endpoint, provider, password in (("storage.googleapis.com", "GCS", "pw"),
                                             ("storage.me-central2.rep.googleapis.com", "GCS", "pw"),
                                             ("s3.amazonaws.com", "Other", "pw"),
                                             # any password config.xml keeps, as 1.1 took it
                                             ("storage.googleapis.com", "GCS", "p\tw\x7f\nx")):
            config = ('<?xml version="1.0"?><opnsense><system><backup><s3 version="1.0.0"><enabled>1</enabled>'
                      f'<endpoint>{endpoint}</endpoint><region>auto</region><bucket>bucket</bucket>'
                      '<prefix>fw</prefix><accessKey>AKIDTEST</accessKey><secretKey>x</secretKey>'
                      f'<password>{password}</password><backupcount>60</backupcount></s3></backup></system></opnsense>')
            self.assertEqual(self.run_steps([["migrate"]], config=config)[0], provider, endpoint)

    def test_disabled_backup_saves_without_rclone(self):
        answer = self.run_steps([["setup", self.setup_page(enabled="0")]], env={"S3_RCLONE": "/nonexistent"})[0]
        self.assertEqual(answer["messages"], [])

    def test_a_trailing_line_break_is_refused(self):
        # core compares a number with trailing white space as equal to the match
        for name, label in (("endpoint", "Endpoint"), ("region", "Region"), ("bucket", "Bucket"),
                            ("prefix", "Folder"), ("accessKey", "Access key ID")):
            messages = self.run_steps([["setup", self.setup_page(**{name: "123\n"})]])[0]["messages"]
            self.assertTrue([m for m in messages if m.startswith(label + ": ")], (name, messages))

    def test_a_failed_nightly_backup_is_logged(self):
        # core's nightly run (php CLI) on 26.7 and before stops at a provider that throws
        answers = self.run_steps([["backup"], ["log"]], region="")
        self.assertEqual(answers[0], [], "the providers after this one still run")
        self.assertEqual(len(answers[1]), 1)
        self.assertIn("s3-backup: The S3 settings are not valid: region:", answers[1][0])

    def hostile(self, mode, steps, **options):
        """The steps against a Hostile endpoint in mode; what it was asked is left in self.seen."""
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.cert, self.key)
        self.seen = []
        self.types = []
        handler = type("Handler", (Hostile,), {"mode": mode, "seen": self.seen, "types": self.types, "stored": [],
                                               "deleted": []})
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        # a hanging answer must not hold the test once the provider has given up on it
        server.block_on_close = False
        server.socket = context.wrap_socket(server.socket, server_side=True)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            return self.run_steps(steps, **dict(options, endpoint=f"localhost:{server.server_port}"))
        finally:
            server.shutdown()
            server.server_close()

    def test_hostile_endpoint(self):
        # rclone reads a huge answer of junk as an empty listing; its own output is what the provider caps
        self.assertEqual(self.hostile("large", [["list", "fw/"]])[0], [])
        for mode, provider, expected in (("error", "Other", "AccessDenied: one FORGED"),
                                         ("loop", "Other", "rclone: "),
                                         ("loop", "Cloudflare", "rclone did not finish within 5 seconds"),
                                         ("endless", "Other", "rclone did not finish within 5 seconds"),
                                         ("long", "Other", "rclone sent more output than expected")):
            started = time.monotonic()
            error = self.hostile(mode, [["list", "fw/"]], provider=provider)[0]["error"]
            self.assertIn(expected, error, mode)
            self.assertNotIn("\n", error, "one line, whatever the endpoint sends")
            self.assertLess(len(error), 300)
            self.assertLess(time.monotonic() - started, 15, mode)

    def test_a_large_folder_lists(self):
        self.assertEqual(len(self.hostile("many", [["list", "fw/"]])[0]), 120000)

    def test_other_files_in_the_folder_are_not_read(self):
        self.assertEqual(self.hostile("others", [["list", "fw/"]])[0], [])

    def test_a_huge_error_is_read_only_in_part(self):
        error = self.hostile("huge-error", [["list", "fw/"]], memory="64M")[0]["error"]
        self.assertTrue(error.startswith("rclone: "), error[:300])
        self.assertLess(len(error), 300)

    def test_a_busy_endpoint_is_tried_twice(self):
        self.hostile("busy", [["list", "fw/"]])
        self.assertEqual([method for method, path in self.seen].count("GET"), 2)

    def test_upload_must_show_in_the_listing(self):
        error = self.hostile("catch-all", [["upload", self.local("config-1727000006.xml")]])[0]["error"]
        self.assertEqual(error, "The backup fw/config-1727000006.xml was sent, but the bucket does not list it.")

    def test_old_backups_go_by_name(self):
        answer = self.hostile("", [["upload", self.local("config-1727000005.xml")]], backupcount="1")[0]
        self.assertEqual(answer, ["config-1727000005.xml"])
        deleted = sorted(path.split("?")[0] for method, path in self.seen if method == "DELETE")
        self.assertEqual(deleted, [f"/bucket/fw/config-172700000{i}.xml" for i in (2, 3, 4)])
        self.assertNotIn("HEAD", [method for method, path in self.seen])

    def test_a_refused_upload_names_no_temporary_file(self):
        error = self.hostile("put-403", [["upload", self.local("config-1727000007.xml")]])[0]["error"]
        self.assertIn("AccessDenied", error)
        self.assertNotIn("s3-backup-", error)

    def test_odd_answers_to_a_delete(self):
        # the listing holds the running backup and two older ones, both to go; one is refused
        running = self.local("config-1727000004.xml")
        answers = self.hostile("delete-403", [["upload", running], ["log"]], backupcount="1")
        error = answers[0]["error"]
        self.assertTrue(error.startswith("The backup is stored, but removing older backups failed: rclone: "), error)
        self.assertIn("AccessDenied", error)
        self.assertEqual(answers[1], ["s3-backup: removed fw/config-1727000003.xml"], "what did go is logged")

    def test_a_delete_must_show_in_the_listing(self):
        answers = self.hostile("delete-200", [["upload", self.local("config-1727000004.xml")], ["log"]],
                               backupcount="1")
        self.assertEqual(answers[0]["error"],
                         "The backup is stored, but removing older backups failed: The bucket still lists 2 of them.")
        self.assertEqual(answers[1], [], "nothing logged as removed")

    def test_a_failed_check_after_removing_says_so(self):
        answers = self.hostile("list-once", [["upload", self.local("config-1727000004.xml")], ["log"]],
                               backupcount="1")
        error = answers[0]["error"]
        self.assertTrue(error.startswith("The backup is stored, but removing older backups failed: The bucket could not "
                                         "be listed afterwards: rclone: "), error)
        self.assertEqual(answers[1], [], "what went is not known")

    def test_a_backup_already_gone_counts_as_removed(self):
        answers = self.hostile("delete-404", [["upload", self.local("config-1727000004.xml")], ["log"]],
                               backupcount="1")
        self.assertEqual(answers[0], ["config-1727000004.xml"])
        self.assertEqual(answers[1], ["s3-backup: removed fw/config-1727000003.xml",
                                      "s3-backup: removed fw/config-1727000002.xml"])

    def test_a_failed_check_says_the_backup_was_sent(self):
        error = self.hostile("list-once", [["upload", self.local("config-1727000008.xml")]])[0]["error"]
        self.assertTrue(error.startswith("The backup fw/config-1727000008.xml was sent, but the bucket could not be "
                                         "listed: rclone: "), error)
        self.assertIn("AccessDenied", error)

    def test_an_etag_that_is_not_the_md5_is_accepted(self):
        answer = self.hostile("kms", [["upload", self.local("config-1727000005.xml")]])[0]
        self.assertEqual(answer, ["config-1727000005.xml", "config-1727000004.xml", "config-1727000003.xml"])

    def test_a_backup_is_sent_as_bytes(self):
        # as 1.1 sent it; it is not XML, whatever its name says
        self.hostile("", [["upload", self.local("config-1727000005.xml")]])
        self.assertEqual(self.types, ["application/octet-stream"])

    def test_a_killed_rclone_is_said(self):
        # e.g. out of memory; timeout(1) exits 128 + the signal on FreeBSD 14 and dies of it on 15
        killed = os.path.join(self.tmp, "killed")
        with open(killed, "w") as handle:
            handle.write("#!/bin/sh\nkill -KILL $$\n")
        os.chmod(killed, 0o755)
        error = self.run_steps([["list", "fw/"]], env={"S3_RCLONE": killed})[0]["error"]
        self.assertEqual(error, "rclone was stopped by signal 9.")

    def test_a_404_names_no_unknown_provider_as_a_missing_bucket(self):
        self.assertEqual(self.hostile("404", [["list", "fw/"]])[0]["error"], "The endpoint has no bucket bucket.")
        error = self.hostile("404", [["list", "fw/"]], provider="Nope")[0]["error"]
        self.assertEqual(error, "rclone knows no S3 provider named Nope.")

    def test_rclone_s_log_is_capped(self):
        # an endpoint can make rclone log without end
        temp, sizes, done = tempfile.mkdtemp(dir=self.tmp), [0], threading.Event()

        def watch():
            while not done.is_set():
                for name in os.listdir(temp):
                    if name.startswith("s3-backup-"):
                        try:
                            sizes.append(os.path.getsize(os.path.join(temp, name)))
                        except OSError:
                            pass
                time.sleep(0.05)
        threading.Thread(target=watch, daemon=True).start()
        try:
            error = self.hostile("odd", [["list", "fw/"]], env={"TMPDIR": temp})[0]["error"]
        finally:
            done.set()
        self.assertEqual(error, "rclone did not finish within 5 seconds.")
        self.assertGreater(max(sizes), 1 << 20, "it logged")
        self.assertLessEqual(max(sizes), 8 << 20)

    def test_no_temp_files_left(self):
        temp = tempfile.mkdtemp(dir=self.tmp)
        env = {"TMPDIR": temp}
        self.run_steps([["upload", self.local("config-1727000040.xml")]], env=env, prefix="fw18")
        self.run_steps([["upload", self.local("config-1727000041.xml")]], env=env, prefix="fw18", secretKey="wrong")
        self.hostile("endless", [["list", "fw/"]], env=env)
        self.assertEqual([name for name in os.listdir(temp) if name.startswith("s3-backup-")], [])


if __name__ == "__main__":
    unittest.main()
