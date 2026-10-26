#!/usr/local/bin/python3

"""
Copyright (C) 2026 Greelan
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.

--

Poll firewall state, compare it with the previous run and push the changes
to the Apprise channels configured under Services: Notify.

  notify.py check             poll and send, retrying earlier failures
  notify.py boot              report that the firewall has started
  notify.py status            what the last run recorded (JSON)
  notify.py summary <uuid>    send one channel's summary of its period so far, without ending it
  notify.py reports           archived summaries (JSON)
  notify.py report <name>     one archived summary's page, base64 (JSON)
  notify.py delete <name>     delete an archived summary (JSON)
  notify.py test <uuid>       send a test message to one channel (JSON result)
  notify.py services          Apprise services and their URL fields (JSON)
  notify.py describe <uuid>   service and non-secret fields of a saved channel (JSON)
  notify.py parse <file>      the same for a URL handed over in a JSON file
  notify.py build <file>      compose and check a channel URL from a JSON request (JSON)

Settings are read from the saved configuration, so a test works before the
settings are applied. Transitions (gateway, CARP, Monit, System Status) are
only reported once a previous state exists; the first poll records a baseline.
"""

import base64
import collections
import contextlib
import enum
import datetime
import functools
import html
import http.client
import ipaddress
import json
import os
import re
import socket
import stat
import sys
import syslog
import time
import traceback
import urllib.parse
import xml.etree.ElementTree as ET

# Apprise, Markdown and PyYAML are vendored under lib/ (pure-Python), so the plugin
# works with whichever Python the OPNsense series ships
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "lib"))

from common import (FIRMWARE_CHANGES, LINK_UP, addresses, carp_states, carp_vhids, clock,  # noqa: E402
                    command_output, configctl, configctl_json, duration, firmware_changes,
                    firmware_product, interfaces, link_states, log, message, pf_states, prune_stale, quiet,
                    read_firmware, service_states, setting, stale_tmp, system_status, write_private)
from summary import (REPORT_NAME, REPORTS_DIR, SAMPLE_SECONDS, SUMMARY_TRIES, add_events,  # noqa: E402
                     archive_report, archived_reports, build_summary, latest, prune_archive, monit_allowed,
                     remove_report, report_graphs, report_page, standby_periods, subscribed, summary_channels,
                     update_summaries)

CONFIG = "/conf/config.xml"
STATE = "/var/db/notify/state.json"
SETTINGS_CACHE = "/var/db/notify/settings.json"
SETTINGS_SCRIPT = "/usr/local/opnsense/scripts/OPNsense/Notify/settings.php"
SETTINGS_FORMAT = 5
# everything else comes through configd; these have no action to ask. Monit's status is read from
# its socket as core's Monit status page does, and logs are followed on from where the last check
# stopped, which core's log query cannot do
MONIT_SOCKET = "/var/run/monit.sock"
AUDIT_LOG = "/var/log/audit"
IDS_LOG = "/var/log/suricata/eve.json"
# battery faults, as NUT's flags are spelled out below and as apcupsd reports them
UPS_FAULTS = ("low battery", "replace", "lowbatt")
# NUT's flags, spelled out (apcupsd already reports words)
UPS_FLAGS = {"OL": "online", "OB": "on battery", "LB": "low battery", "RB": "replace battery",
             "CHRG": "charging", "DISCHRG": "discharging", "BYPASS": "on bypass", "CAL": "calibrating",
             "OFF": "off", "OVER": "overloaded", "TRIM": "trimming voltage", "BOOST": "boosting voltage"}

# backoff between delivery attempts, then hourly until RETRY_SECONDS is up
RETRY_DELAYS = (60, 120, 300, 600, 1800, 3600)
RETRY_SECONDS = 86400
QUEUE_MAX = 100
DIGEST_LINES = 20
DIGEST_CHARS = 800
CERT_INTERVAL = 3600
# System Status entries change slowly and cost a PHP call to collect
STATUS_INTERVAL = 300
# the host list is a database read; new devices are not urgent
DEVICE_INTERVAL = 300
# field holding the query part of a built URL, e.g. priority=high&format=markdown
QUERY_FIELD = "__query"
# plugins sending to any receiver (subclasses included), where the secret is often the path (a
# Home Assistant webhook's id, say), which Apprise does not mask: the saved URL shown leaves it out
PATH_SECRET = ("NotifyJSON", "NotifyForm", "NotifyXML")
# held by a running check; a test or summary waits for it rather than run beside one
LOCK = "/var/run/notify.lock"
# URL arguments Apprise opens as a file on every send, by plugin class (subclasses included);
# elsewhere, e.g. MSG91 or SendGrid, a template is only an ID. The dialog takes the file's
# contents, which are stored with the channel and written under KEY_DIR at send time; the URL
# then carries KEY_MARKER. Any other local path is refused, so a channel cannot make root read a
# file of its choosing. Checked against this Apprise; the tests fail on another until it is again.
# Before raising it, also confirm the Apprise internals this script uses still exist and behave
# the same: plugins.url_to_dict and N_MGR, utils.parse's parse_qsd, parse_urls, VALID_URL_RE and
# NOTIFY_CUSTOM_*_TOKENS (see apprise_view, check_url, query_pairs, custom_arg), email's
# AppriseSMTPController.sendmail, its _socket and logger (see partly_sent) and PGP_MODES (see
# apprise1_notes), and that Apprise.notify still applies emojis before convert_between (see
# with_link); and that plugins still hold their settings as attributes, which an import compares
# (see same_settings).
FILE_ARGS_APPRISE = "2.1.0"
FILE_ARGS = {
    "NotifyDiscord": ("template",), "NotifyTelegram": ("template",), "NotifySlack": ("template",),
    "NotifyWorkflows": ("template",), "NotifyFCM": ("keyfile",), "NotifyVapid": ("keyfile", "subfile"),
    "NotifyEmail": ("pgppub", "pgpprv"),
}
# services Apprise offers although each URL fails without one of these modules, which it only
# recommends; left out while none is installed, as OPNsense ships neither of AMQP's
NEEDS_ONE_OF = {"NotifyAMQP": ("pika", "proton")}
# tokens Apprise masks in its own URL without marking them private, e.g. Mastodon's access token or
# a login; kept out of the browser as the private ones are. The tests read them from Apprise's url()
PRIVATE_TOKENS = {
    "NotifyMastodon": ("token",), "NotifyMisskey": ("token",), "NotifySMSEagle": ("token",),
    "NotifyBulkSMS": ("token_id",), "NotifyPlivo": ("auth_id", "token"), "NotifyLametric": ("app_token",),
    "NotifyBulkVS": ("user",), "NotifySMSC": ("user",), "NotifySerwerSMS": ("user",), "NotifyRocketChat": ("webhook",),
    "NotifyPagerDuty": ("source", "component"), "NotifyVoipms": ("from_phone",),
}
# options Apprise reads as unset when left out, not as the default its details give, e.g. emojis:
# Discord escapes :name: only for no
UNSET_ARGS = ("emojis",)
# files that may instead be fetched from an https address; private keys are never fetched
REMOTE_FILE_ARGS = ("template", "pgppub")
# what each file holds, as the dialog labels it and hints at it: (plugin class or None, argument)
FILE_LABELS = {
    (None, "template"): ("Template (JSON)", "Paste the JSON message template, or give an https:// address"),
    ("NotifyFCM", "keyfile"): ("Service account key (JSON)", "Paste the Firebase service account key"),
    ("NotifyVapid", "keyfile"): ("Private key (PEM)", "Paste the VAPID private key"),
    ("NotifyVapid", "subfile"): ("Subscriptions (JSON)", "Paste the push subscriptions"),
    (None, "pgppub"): ("PGP public key", "Paste the ASCII-armored public key, or give an https:// address"),
    (None, "pgpprv"): ("PGP private key", "Paste the ASCII-armored private key"),
}
KEY_MARKER = "stored"
KEY_DIR = "/var/db/notify/keys"
# ends each message Apprise logs, so one holding a line break (a quoted value, a server's reply)
# is read whole; no logged value can know it
LOG_MARK = f"\0{os.urandom(8).hex()}\0"
# a model UUID, as it names the channel's files
CHANNEL_ID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
KEY_MAX = 64 * 1024
# the web interface hands a build or import request over in its tmp (AppConfig tempDir); only such a
# file is read
TEMP_DIR = "/var/lib/php/tmp"
REQUEST_MAX = 1024 * 1024
# recorded state older than this predates a pause (disabled, or the firewall was off),
# so it is dropped rather than compared against
STALE_SECONDS = 3600
# WireGuard online within this, then stale, as in core
HANDSHAKE_SECONDS = 300
# lines or alerts read from a log in one pass, so a busy log cannot stall a check
LOG_LINES = 500
LOG_BYTES = 2 * 1024 * 1024
# scanned back for marked lines, e.g. IDS alerts
KEEP_BYTES = 64 * 1024 * 1024
# devices remembered, oldest dropped first
DEVICES_MAX = 4096
SYSLOG_DIR = "/var/log"
# audit (logins), filterlog, and our own
SYSLOG_SKIP = ("audit", "filter", "notify")
SEVERITIES = ("emergency", "alert", "critical", "error", "warning", "notice", "info", "debug")
# a repeated log message is held this long
SYSLOG_HOLD = 3600
# per check; more are listed in one
LOG_MESSAGES = 20
SEEN_MAX = 1000

AUTH_FAILURE = ("authentication failed", "could not authenticate", "unknown user", "invalid credentials")
AUTH_SUCCESS = ("authenticated successfully",)
AUTH_LOCKOUT = ("lockout", "blocked for")
# packages named individually before falling back to counts
FIRMWARE_PACKAGES = 8

# Monit error bits in the order Monit reports them (src/event.c Event_Table): bit, failed, changed
MONIT_EVENTS = (
    (0x20000, "Action done", "Action done"),
    (0x4000000, "Download bytes exceeded", "Download bytes changed"),
    (0x8000000, "Upload bytes exceeded", "Upload bytes changed"),
    (0x1, "Checksum failed", "Checksum changed"),
    (0x20, "Connection failed", "Connection changed"),
    (0x8000, "Content failed", "Content match"),
    (0x800, "Data access error", "Data access changed"),
    (0x1000, "Execution failed", "Execution changed"),
    (0x2000, "Filesystem flags failed", "Filesystem flags changed"),
    (0x100, "GID failed", "GID changed"),
    (0x100000, "Heartbeat failed", "Heartbeat changed"),
    (0x4000, "ICMP failed", "ICMP changed"),
    (0x10000, "Monit instance failed", "Monit instance changed"),
    (0x400, "Invalid type", "Type changed"),
    (0x800000, "Link down", "Link changed"),
    (0x200, "Does not exist", "Existence changed"),
    (0x10000000, "Download packets exceeded", "Download packets changed"),
    (0x20000000, "Upload packets exceeded", "Upload packets changed"),
    (0x40, "Permission failed", "Permission changed"),
    (0x40000, "PID failed", "PID changed"),
    (0x80000, "PPID failed", "PPID changed"),
    (0x2, "Resource limit matched", "Resource limit changed"),
    (0x2000000, "Saturation exceeded", "Saturation changed"),
    (0x10, "Size failed", "Size changed"),
    (0x1000000, "Speed failed", "Speed changed"),
    (0x200000, "Status failed", "Status changed"),
    (0x4, "Timeout", "Timeout changed"),
    (0x8, "Timestamp failed", "Timestamp changed"),
    (0x80, "UID failed", "UID changed"),
    (0x400000, "Uptime failed", "Uptime changed"),
    (0x40000000, "Does exist", "Existence changed"),
)
MONIT_MONITOR_YES = 0x1
MONIT_MONITOR_INIT = 0x2

# a service is reported once stopped this long over two reads; restarts take seconds
SERVICE_HOLD = 240
# with all services running, they are read every other one-minute check
SERVICE_READ = 120
# checks run on a whole interval but not to the second, so a hold or retry that should end on one does
CHECK_SLACK = 30
# a stop first seen this soon after boot, and not seen running since, is one after boot
SERVICE_BOOT = 1800

# System Status codes (OPNsense\System\SystemStatusCode)
STATUS_LEVELS = {"error": -1, "warning": 0, "notice": 1}
STATUS_TYPES = {-1: "failure", 0: "warning", 1: "info"}


def text(node, path, default=""):
    value = node.findtext(path) if node is not None else None
    return value if value is not None else default


def load_config():
    """Settings from the models, via settings.php; cached until config.xml or settings.php changes."""
    try:
        stat, script = os.stat(CONFIG), os.stat(SETTINGS_SCRIPT)
        source = [stat.st_mtime_ns, stat.st_size, script.st_mtime_ns, script.st_size, SETTINGS_FORMAT]
    except OSError:
        source = None
    if source is not None:
        try:
            with open(SETTINGS_CACHE) as handle:
                cached = json.load(handle)
            if cached.get("source") == source:
                return cached["config"]
        except (OSError, ValueError, KeyError):
            pass

    output = command_output([SETTINGS_SCRIPT], timeout=60)
    try:
        config = json.loads(output or "")
    except ValueError as error:
        log(syslog.LOG_ERR, f"settings could not be read: {error if output else 'settings.php failed'}")
        return None

    if source is not None:
        save_cache({"source": source, "config": config})
    return config


def save_cache(payload):
    """The cache holds the channel URLs, so it is written private."""
    try:
        write_private(SETTINGS_CACHE, json.dumps(payload))
    except OSError:
        pass  # without a cache the next run simply asks again


def load_state():
    try:
        with open(STATE) as handle:
            state = json.load(handle)
        return state if isinstance(state, dict) else {}
    except (OSError, ValueError):
        return {}


def fresh_state():
    """The recorded state, keeping only the queue, summary and service data once it is too old to
    compare against, and the certificate and firmware levels, which would otherwise be told again;
    stopped services then still get their end."""
    state = load_state()
    if int(time.time()) - state.get("stamp", 0) > STALE_SECONDS:
        # queued items expire on their own
        state = {key: state[key] for key in ("queue", "summary", "service", "certificate", "firmware")
                 if key in state}
    return state


def save_state(state):
    """The queue holds message bodies, so the state is written private like the cache."""
    write_private(STATE, json.dumps(state))


def follow(path, previous, keep=None):
    """New lines since the last pass (only those with keep), the position to remember, and (lines
    missed, bytes skipped). A rotated log is finished first, found by inode; inode 0 means from
    the start."""
    try:
        stat = os.stat(path)
    except OSError:
        return [], previous, (0, 0)
    state = {"inode": stat.st_ino, "offset": stat.st_size, "path": path}
    if previous.get("inode") is None:
        return [], state, (0, 0)  # first sight of this file, start from the end
    lines: list = []
    missed, skipped = 0, 0
    if previous["inode"] and previous["inode"] != stat.st_ino:
        old = rotated(path, previous["inode"])
        read = read_new(old, previous.get("offset", 0), keep) if old is not None else None
        if read is not None:
            lines, missed, skipped = read[0], read[1], read[2]
        # else compressed; either way the new file is read from its start
        previous = {"inode": stat.st_ino, "offset": 0, "path": path}
    read = read_new(path, previous.get("offset", 0), keep)
    if read is None:
        return lines, previous, (missed, skipped)
    lines += read[0]
    state["offset"] = read[3]
    missed += read[1] + max(len(lines) - LOG_LINES, 0)
    return lines[-LOG_LINES:], state, (missed, skipped + read[2])


def find_mark(data, keep, start, end):
    if isinstance(keep, bytes):
        return data.find(keep, start, end)
    match = keep.search(data, start, end)
    return match.start() if match else -1


def read_new(path, position, keep=None):
    """(lines, lines missed, bytes skipped, end offset) from position; a flood is skipped and only
    lines matching keep (bytes, or a bytes pattern for a line's start) are decoded."""
    try:
        with open(path, "rb") as handle:
            size = os.fstat(handle.fileno()).st_size
            if position > size:
                position = 0  # truncated
            # markers are cheap to find, so scan further
            start = max(position, size - (KEEP_BYTES if isinstance(keep, bytes) else LOG_BYTES))
            handle.seek(start)
            if start > position:
                handle.readline()  # the rest of a line cut by the skip
                start = handle.tell()
            kept: collections.deque = collections.deque(maxlen=LOG_LINES)
            total = 0
            carry = b""  # an unfinished last line waits
            if keep is not None:
                # find markers in large blocks, in C
                while True:
                    block = handle.read(4 * 1024 * 1024)
                    if not block:
                        break
                    data = carry + block
                    cut = data.rfind(b"\n") + 1
                    at = find_mark(data, keep, 0, cut)
                    while at >= 0:
                        begin = data.rfind(b"\n", 0, at) + 1
                        stop = data.find(b"\n", at, cut)
                        stop = cut if stop < 0 else stop + 1
                        total += 1
                        kept.append(data[begin:stop])
                        at = find_mark(data, keep, stop, cut)
                    carry = data[cut:]
            else:
                for line in handle:
                    if not line.endswith(b"\n"):
                        carry = line
                        break
                    total += 1
                    kept.append(line)
            end = handle.tell() - len(carry)
    except OSError:
        return None
    return [line.decode("utf-8", "replace") for line in kept], total - len(kept), start - position, end


def rotated(path, inode):
    """Where a log was rotated to, found by the inode it had; a compressed copy is not read."""
    folder = os.path.dirname(path)
    try:
        names = os.listdir(folder)
    except OSError:
        return None
    for name in names:
        candidate = os.path.join(folder, name)
        if candidate == path or name.endswith((".gz", ".bz2", ".xz", ".zst")):
            continue
        try:
            if os.stat(candidate).st_ino == inode:
                return candidate
        except OSError:
            continue
    return None


def left_out(event, what, missed, skipped):
    """A note that a log pass left lines out, or nothing."""
    parts = []
    if missed:
        parts.append(f"{missed} {what} before the latest {LOG_LINES}")
    if skipped:
        parts.append(f"{skipped // (1024 * 1024) or 1} MB of log")
    if not parts:
        return []
    # sent, not counted
    return [dict(message(event, "warning", f"Some {what} were not checked",
                         "The log grew faster than it is read, so these were passed over: " + "; ".join(parts) + "."),
                 note=True)]


def audit_log():
    """Today's audit log, named by syslog-ng as audit_YYYYMMDD.log."""
    return os.path.join(AUDIT_LOG, time.strftime("audit_%Y%m%d.log"))


# ------------------------------------------------------------------ collectors
# each takes (config, previous state or None) and returns (new state, messages);
# returning the previous state unchanged means "no data this time"


def gateway_level(status, degraded):
    """What a dpinger status means to us, or None while it is still pending."""
    if status == "none":
        return "up"
    if status in ("delay", "loss", "delay+loss"):
        return "degraded" if degraded else "up"
    if status == "down":
        return "down"
    if status == "force_down":
        return "forced"
    return None


def check_gateway(config, previous):
    data = configctl_json("interface", "gateways", "status")
    if not isinstance(data, dict):
        return previous, []
    degraded = config["general"].get("gatewayDegraded", "0") == "1"
    hold = setting(config["general"], "gatewayHold", 0)
    now = int(time.time())
    current, messages = {}, []
    for name, gateway in data.items():
        status = str(gateway.get("status", ""))
        level = gateway_level(status, degraded)
        last = (previous or {}).get(name)
        if level is None:
            if last:
                current[name] = last
            continue
        if last is None:
            current[name] = {"level": level, "since": now}
            continue
        if last.get("level") == level:
            current[name] = dict(last)
            current[name].pop("pending", None)  # back to where it was, nothing to report
            current[name].pop("pending_since", None)
            continue
        if hold:
            if last.get("pending") != level:
                current[name] = dict(last, pending=level, pending_since=now)
                continue
            if now - last.get("pending_since", now) < hold:
                current[name] = dict(last)  # still waiting for the level to settle
                continue
        current[name] = {"level": level, "since": last.get("pending_since", now) if hold else now}
        if "forced" in (level, last["level"]):
            continue  # marked down by hand
        detail = f"Status: {gateway.get('status_translated', status)}"
        if gateway.get("monitor", "~") != "~":
            detail += (f"\nMonitor: {gateway['monitor']}, RTT {gateway.get('delay', '~')},"
                       f" loss {gateway.get('loss', '~')}")
        outage = f"Down for {duration(now - last['since'])} (since {clock(last['since'])})."
        if level == "down":
            messages.append(message("gateway", "failure", f"Gateway {name} is down", detail))
        elif level == "degraded" and last["level"] == "down":
            messages.append(message("gateway", "warning", f"Gateway {name} is back up with issues",
                                    f"{outage}\n{detail}"))
        elif level == "degraded":
            messages.append(message("gateway", "warning", f"Gateway {name} is degraded", detail))
        elif last["level"] == "down":
            messages.append(message("gateway", "success", f"Gateway {name} is back up", outage))
        else:
            messages.append(message("gateway", "success", f"Gateway {name} has recovered", detail))
    return current, messages


def check_config(config, previous):
    revision = config.get("revision", {})
    stamp = revision.get("time", "")
    if not stamp:
        return previous, []
    current = {"time": stamp}
    if previous is None or previous.get("time") == stamp:
        return current, []
    who = revision.get("username") or "someone"
    what = revision.get("description") or "Configuration saved."
    return current, [message("config", "info", f"Configuration changed by {who}", what)]


def check_firmware(config, previous):
    """Firmware changes a check found; read at most every STATUS_INTERVAL, as core's product script
    runs several commands. {"key": what was found, "checked": when}."""
    previous = previous if isinstance(previous, dict) else {"key": previous or ""}  # a key alone before
    now = int(time.time())
    if now - previous.get("checked", 0) < STATUS_INTERVAL:
        return previous, []
    data = read_firmware()
    if data is None or data.get("connection") != "ok":
        return dict(previous, checked=now), []
    changes = firmware_changes(data)
    major = data.get("upgrade_major_version") or ""
    key = json.dumps([sorted(k for k, _, _ in changes), major]) if changes or major else ""
    state = {"key": key, "checked": now}
    if not key or key == previous.get("key"):
        return state, []
    reasons = [reason for _, _, reason in changes]
    counts = ", ".join(f"{reasons.count(r)} {r}" for _, r in FIRMWARE_CHANGES if r in reasons)
    lines = [line for _, line, _ in changes] if len(changes) <= FIRMWARE_PACKAGES else \
        [f"{len(changes)} package changes: {counts}."]
    if major:
        lines.append(f"Major upgrade to {major} is available.")
    if data.get("upgrade_needs_reboot") == "1" or data.get("needs_reboot") == "1":
        lines.append("The update requires a reboot.")
    return state, [message("firmware", "info", "Firmware updates are available", "\n".join(lines))]


def login_source(line):
    """Where a login came from. From 26.7.8 on core ends its own lines with the address, or with -
    when there is none; that end is preferred, as the user name before it is the caller's to choose."""
    ending = re.search(r" at (\S+)$", line)
    if ending:
        if ending.group(1) == "-":
            return ""
        with contextlib.suppress(ValueError):
            ipaddress.ip_address(ending.group(1))
            return ending.group(1)
    found = re.search(r"\bfrom '?([0-9A-Fa-f.:]+)", line)
    return found.group(1) if found else ""


def check_auth(config, previous):
    logins = config["general"].get("authLogins", "0") == "1"
    previous, path, lines = previous or {}, audit_log(), []
    missed, skipped = 0, 0
    if previous.get("path") and previous["path"] != path:
        lines, _, (missed, skipped) = follow(previous["path"], previous)  # the rest of the day before
        previous = {"inode": 0}  # read the new day's file from its start
    more, state, (more_missed, more_skipped) = follow(path, previous)
    lines += more
    messages = left_out("auth", "login events", missed + more_missed, skipped + more_skipped)
    for line in lines:
        body = line.strip()
        lowered = body.lower()
        user = re.search(r"\buser '?([^'\s]+)", body, re.I)
        facts = {"user": user.group(1) if user else "", "source": login_source(body)}
        if any(hint in lowered for hint in AUTH_LOCKOUT):
            messages.append(message("auth", "failure", "Login blocked", body, dict(facts, outcome="Blocked")))
        elif any(hint in lowered for hint in AUTH_FAILURE):
            messages.append(message("auth", "warning", "Failed login", body, dict(facts, outcome="Failed")))
        elif logins and any(hint in lowered for hint in AUTH_SUCCESS):
            messages.append(message("auth", "info", "Login", body, dict(facts, outcome="Succeeded")))
    return state, messages


def check_certificate(config, previous):
    previous = previous or {}
    now = int(time.time())
    if now - previous.get("checked", 0) < CERT_INTERVAL:
        return previous, []
    days = setting(config["general"], "certDays", 14)
    seen, messages = {}, []
    for item in config.get("certificates", []):
        expires, key = item["expires"], item["key"]
        left = expires - now
        stage = "expired" if left <= 0 else ("expiring" if left <= days * 86400 else "")
        seen[key] = f"{expires}:{stage}"
        if not stage or previous.get("items", {}).get(key) == seen[key]:
            continue
        label, descr = item["label"], item["description"]
        when = time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(expires))
        if stage == "expired":
            messages.append(message("certificate", "failure", f"{label} {descr} has expired",
                                    f"Expired {when}."))
        else:
            messages.append(message("certificate", "warning",
                                    f"{label} {descr} expires in {max(left // 86400, 0)} day(s)",
                                    f"Expires {when}."))
    return {"checked": now, "items": seen}, messages


def check_status(config, previous):
    previous = previous or {}
    now = int(time.time())
    if now - previous.get("checked", 0) < STATUS_INTERVAL:
        return previous, []
    data = system_status()
    if data is None:
        return previous, []
    seen = previous.get("items")
    threshold = STATUS_LEVELS.get(config["general"].get("statusLevel", "warning"), 0)
    current, messages, unread = {}, [], set()
    for name, item in data.items():
        try:
            code = int(item.get("statusCode"))
        except (TypeError, ValueError):
            unread.add(name)
            continue
        if code > threshold:
            continue
        body = re.sub(r"<[^>]+>", "", str(item.get("message", ""))).strip()
        title = str(item.get("title", name))
        # the timestamp moves for each new occurrence, where the message rarely does
        current[name] = [code, body, str(item.get("timestamp", "")), title]
        if seen is None or seen.get(name) == current[name]:
            continue
        messages.append(message("status", STATUS_TYPES.get(code, "info"), title, body))
    for name, was in (seen or {}).items():
        # below the level is resolved, unless the level just changed: raising it hides, not resolves
        if name in current or name in unread or (name in data and previous.get("level", threshold) != threshold):
            continue
        gone = was[3] if len(was) > 3 else name
        messages.append(message("status", "success", f"{gone} is resolved",
                                f"Was: {was[1]}" if was[1] else ""))
    return {"checked": now, "items": current, "level": threshold}, messages


class UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, path):
        super().__init__("localhost", timeout=30)
        self.path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.path)


def monit_status(config):
    """Monit's status XML, or None. From 26.7.8 on core's action reads it; before that, or when the
    action has no answer (its JSON cannot carry e.g. a program check's output that is not UTF-8),
    Monit's socket is asked with the httpd credentials, as core's status page used to."""
    if "monit fetch" in (configctl_json("configd", "actions", "json") or {}):
        answer = configctl_json("monit", "fetch", "xml")
        if isinstance(answer, dict) and answer.get("http_code") == 200 and answer.get("response"):
            return answer["response"]
    headers = {}
    credentials = config.get("monit", {})
    username, password = credentials.get("username", ""), credentials.get("password", "")
    if username and password:
        token = base64.b64encode(f"{username}:{password}".encode()).decode()
        headers["Authorization"] = f"Basic {token}"
    try:
        connection = UnixHTTPConnection(MONIT_SOCKET)
        connection.request("GET", "/_status?format=xml", headers=headers)
        response = connection.getresponse()
        return response.read() if response.status == 200 else None
    except (OSError, http.client.HTTPException):
        return None


def check_monit(config, previous):
    if not os.path.exists(MONIT_SOCKET):
        return previous, []
    status = monit_status(config)
    try:
        root = ET.fromstring(status) if status else None
    except ET.ParseError:
        root = None
    if root is None:
        return previous, []
    current, messages = {}, []
    for service in root.findall("service"):
        name = text(service, "name")
        try:
            monitor = int(text(service, "monitor", "0"))
            error = int(text(service, "status", "0"))
            hint = int(text(service, "status_hint", "0"))
        except ValueError:
            continue
        last = (previous or {}).get(name)
        if not monitor & MONIT_MONITOR_YES or monitor & MONIT_MONITOR_INIT:
            if last is not None:
                current[name] = last
            continue
        failures = [changed if hint & bit else failed for bit, failed, changed in MONIT_EVENTS if error & bit]
        current[name] = " | ".join(failures)
        if previous is None or last == current[name] or (last is None and not failures):
            continue
        if failures:
            found = message("monit", "failure", f"Monit: {name}", current[name])
        else:
            found = message("monit", "success", f"Monit: {name} has recovered", f"Was: {last}")
        messages.append(dict(found, service=name))
    return current, messages


def booting_or_updating():
    """Booting, as System Status reports it, or a firmware action running, as the Firmware page asks."""
    return "systembooting" in (system_status() or {}) or \
        (configctl("firmware", "running") or "").strip() == "busy"


def check_service(config, previous):
    """Services stopped for SERVICE_HOLD, as the Services widget shows them; not while booting or
    running a firmware action, on a CARP standby or just after a role change. The hold runs on
    uptime, which a clock step does not move."""
    # while any service is stopped, or the end of a stop is held, every check reads, so the end is
    # seen and sent within a minute; otherwise on even minutes, so a check in between, e.g. a gateway
    # alarm's, does not put the next read off
    last = (previous or {}).get("uptime")
    stopped = any(not entry.get("running") for entry in (previous or {}).get("services", {}).values()) \
        or bool((previous or {}).get("ended"))
    if last is not None and not stopped and 0 <= time.monotonic() - last < SERVICE_READ - CHECK_SLACK \
            and round(time.time() / 60) % 2:
        return previous, []
    services = service_states()
    if not services:
        return previous, []  # unread, or empty for a moment: a firewall always has services
    now, uptime = int(time.time()), time.monotonic()
    previous = previous or {}
    # timing carries on from a recent check only; after a reboot, a pause or a lost state, a stop
    # not yet reported is timed again
    continuous = "uptime" in previous and 0 <= uptime - previous["uptime"] <= STALE_SECONDS
    carp = carp_states()
    role = "master" if "MASTER" in carp else ("standby" if "BACKUP" in carp else "")
    hold_until = previous.get("hold", 0.0) if continuous else 0.0
    if continuous and previous.get("role", "") != role:
        hold_until = uptime + SERVICE_HOLD
    # with CARP master only, what this node finds is not sent, so nothing is marked either; and a
    # standby may stop services with its role, e.g. OpenVPN instances bound to CARP, so reports none
    unsent = is_carp_backup(config)
    silent = role == "standby" or unsent
    known = previous.get("services", {})
    if not continuous:
        # uptime may have started over, so a reported stop is timed by the clock from here
        known = {k: dict(v, carried=True) if v.get("reported") else v for k, v in known.items()}
    # ends of reported stops that came while nothing was sent: {key: (label, seconds stopped)}, and
    # the keys of those first seen late, apart so an earlier release still reads the ends
    ended = dict(previous.get("ended", {}))
    late_ends = set(previous.get("late", ()))
    probed = None

    def busy():
        """Asked only while a stop is being timed, and once."""
        nonlocal probed
        if probed is None:
            probed = booting_or_updating()
        return probed

    def stopped_for(entry):
        return now - entry["at"] if entry.get("carried") else uptime - entry["down"]

    current: dict = {}
    messages: list = []
    for key, label, running in services:
        last = known.get(key) or {}
        if last.get("reported") and running:
            ended[key] = (label, stopped_for(last))
            if last.get("late"):
                late_ends.add(key)
            else:
                late_ends.discard(key)
            last = {}
        if running:
            current[key] = {"running": True}
            continue
        if last.get("reported") or (continuous and last and not last.get("running")):
            entry = dict(last)
        else:
            # not seen running since boot: it may not have started, or stopped before a check
            boot = uptime < SERVICE_BOOT and not (continuous and last.get("running"))
            # more than a minute since the last read, so it may have stopped well before
            late = not continuous or uptime - previous.get("uptime", uptime) > 60 + CHECK_SLACK
            entry = {"down": uptime, "since": uptime, "at": now, "seen": 0, "boot": boot, "late": late,
                     "label": label}
        entry["seen"] += 1
        entry.pop("missing", None)
        if entry.get("reported"):
            current[key] = entry
            continue
        if busy():
            entry["since"] = uptime  # the hold starts over once done; the stop keeps its time
        elif not silent and entry["seen"] >= 2 and uptime >= hold_until - CHECK_SLACK \
                and uptime - entry["since"] >= SERVICE_HOLD - CHECK_SLACK:
            entry["reported"] = True
            if entry["boot"]:
                title = f"{label} is not running after boot"
                body = f"Not seen running since the boot at {clock(now - uptime)}."
            else:
                title = f"{label} has stopped"
                body = f"Stopped since {clock(now - stopped_for(entry))}{' or earlier' if entry['late'] else ''}."
            messages.append(message("service", "failure", title, body, {"service": label}))
        current[key] = entry
    for key, entry in known.items():
        if key in current or key in ended or not entry.get("reported"):
            continue
        if unsent:
            current[key] = entry
        elif not entry.get("missing"):
            current[key] = dict(entry, missing=True)  # one read without it may be a list half made
        else:
            # disabled, removed, or an instance renamed: say so, rather than leave it open
            messages.append(dict(message("service", "info", f"{entry.get('label', key)} is no longer listed",
                                         f"Stopped for {for_at_least(entry.get('late'))}"
                                         f"{duration(stopped_for(entry))}, then removed from the services."),
                                 note=True))
    if not unsent:
        # sent, not counted again in summaries; an earlier stop's end before any new stop
        messages[:0] = [dict(message("service", "success", f"{label} is running again",
                                     f"Stopped for {for_at_least(key in late_ends)}{duration(stopped)}."), note=True)
                        for key, (label, stopped, *_) in ended.items()]
        ended = {}
    return {"role": role, "hold": hold_until, "services": current, "ended": ended,
            "late": sorted(late_ends & set(ended)), "uptime": uptime}, messages


def for_at_least(late):
    """A stop first seen a while after the read before is timed from then, so it lasted longer."""
    return "at least " if late else ""


def is_carp_backup(config, unknown=True):
    """True when this firewall has CARP virtual IPs and none of them is master; unknown when
    the interfaces could not be read."""
    if config["general"].get("carpMasterOnly", "0") != "1":
        return False
    if interfaces() is None:
        return unknown
    states = carp_states()
    return bool(states) and "MASTER" not in states


def check_vpn(config, previous):
    now = int(time.time())
    current, messages, idle = {}, [], {}
    # settings.php says which VPNs have something configured
    vpn = config.get("vpn") or {"wireguard": True, "openvpn": True}
    peers = configctl_json("wireguard", "show") if vpn.get("wireguard") else {}
    if peers is None:
        # unreadable: keep what was known, rather than report every peer gone
        current.update({k: v for k, v in (previous or {}).items() if k.startswith("WireGuard ")})
    for record in peers.get("records", []) if isinstance(peers, dict) else []:
        if record.get("type") != "peer":
            continue
        name = f"WireGuard {record.get('if', '?')} {str(record.get('public-key', ''))[:12]}"
        try:
            handshake = int(record.get("latest-handshake") or 0)
        except (TypeError, ValueError):
            handshake = 0
        # as core: stale, not down, without traffic
        current[name] = "offline" if not handshake else ("online" if now - handshake <= HANDSHAKE_SECONDS
                                                         else "stale")
        if current[name] == "stale":
            idle[name] = now - handshake
    sessions = configctl_json("openvpn", "connections", "server,client") if vpn.get("openvpn") else {}
    if sessions is None:
        current.update({k: v for k, v in (previous or {}).items() if k.startswith("OpenVPN ")})
    sessions = sessions if isinstance(sessions, dict) else {}
    servers = sessions.get("server")
    for identifier, instance in (servers.items() if isinstance(servers, dict) else []):
        if not isinstance(instance, dict):
            continue
        for client in instance.get("client_list", []) or []:
            current[f"OpenVPN server {identifier} {client.get('common_name', '?')}"] = "up"
    clients = sessions.get("client")
    for identifier, instance in (clients.items() if isinstance(clients, dict) else []):
        if not isinstance(instance, dict):
            continue
        state = str(instance.get("status", "")).lower()
        if state and state != "failed":
            current[f"OpenVPN client {identifier}"] = "up" if state == "connected" else "down"
    for name, level in current.items():
        last = (previous or {}).get(name)
        # before 1.4, down meant stale or never connected
        if name.startswith("WireGuard") and (last, level) in (("up", "online"), ("down", "stale"), ("down", "offline")):
            continue
        if previous is None or last == level or (last is None and level not in ("up", "online")):
            continue  # one first seen down is a baseline, as elsewhere; one first seen up has just connected
        word = VPN_WORDS[level]
        body = f"No handshake for {duration(idle[name])}." if name in idle else ""
        messages.append(message("vpn", "success" if level in ("up", "online") else "warning",
                                f"{name} is {word}", body, {"peer": f"{name}: {word}"}))
    for name in (previous or {}):
        if name not in current and previous[name] in ("up", "online"):
            word = "offline" if name.startswith("WireGuard") else "disconnected"
            messages.append(message("vpn", "warning", f"{name} is {word}", "", {"peer": f"{name}: {word}"}))
    return current, messages


VPN_WORDS = {"up": "connected", "down": "disconnected", "online": "online", "stale": "stale", "offline": "offline"}


def check_syslog(config, previous):
    """Local log lines at or above the chosen severity; audit, filterlog and our own log are
    skipped."""
    threshold = setting(config["general"], "logSeverity", 2)
    kept = latest(config["general"])
    previous = previous or {}
    now, day = int(time.time()), time.strftime("%Y%m%d")
    try:
        names = sorted(n for n in os.listdir(SYSLOG_DIR) if n not in SYSLOG_SKIP)
    except OSError:
        return previous, []

    # the priorities (facility * 8 + severity) at or above the severity
    wanted = re.compile(rb"^<(?:%s)>" % b"|".join(b"%d" % (f * 8 + s) for f in range(24)
                                                  for s in range(threshold + 1)), re.M)
    files: dict = {}
    found: dict = {}
    missed = skipped = 0
    for name in names:
        path = os.path.join(SYSLOG_DIR, name, f"{name}_{day}.log")
        last = previous.get("files", {}).get(name, {})
        if not last and not os.path.isfile(path):
            continue
        lines = []
        if last.get("path") and last["path"] != path:
            lines, _, (count, passed) = follow(last["path"], last, wanted)  # the rest of the day before
            missed, skipped = missed + count, skipped + passed
            last = {"inode": 0}  # read the new day's file from its start
        more, files[name], (count, passed) = follow(path, last, wanted)
        missed, skipped = missed + count, skipped + passed
        for line in lines + more:
            match = re.match(r"<(\d+)>\d* (\S+) \S+ (\S+) \S+ \S+ (?:-|\[.*?\]) ?(.*)", line.strip())
            if match:
                key = (name, match.group(3), match.group(4).strip(), int(match.group(1)) % 8)
                try:
                    at = int(datetime.datetime.fromisoformat(match.group(2)).timestamp())
                except ValueError:
                    at = now
                found.setdefault(key, []).append(at)
    # repeats within the hold are counted, not sent
    seen = {k: t for k, t in previous.get("seen", {}).items() if now - t < SYSLOG_HOLD}
    # the most severe sent of each; 0 for one seen before this was kept, so it is held as then
    levels = {k: v for k, v in previous.get("levels", {}).items() if k in seen}
    messages: list = []
    extra: list = []
    sent = 0
    for (name, program, text, severity), times in sorted(found.items(), key=lambda kv: kv[0][3]):
        count = len(times)
        # each second it was logged in, with how many times, the latest as many as a summary lists
        logged = sorted(collections.Counter(times).items())[-kept:] if kept else []
        repeat = f"{program}\t{text}"[:300]
        held = repeat in seen and severity >= levels.get(repeat, 0)
        body = f"{SEVERITIES[severity].capitalize()} in the {name} log: {text}"
        if count > 1:
            body += f"\n(Logged {count} times.)"
        found_now = dict(message("syslog", "failure" if severity <= 2 else "warning", f"{program}: {text[:100]}",
                                 body, {"program": program}), count=count, logged=logged)
        if held or sent >= LOG_MESSAGES:
            if not held:
                extra.append(f"{program}: {text[:100]}")
            messages.append(dict(found_now, quiet=True))
        else:
            messages.append(found_now)
            sent += 1
        if not held:
            seen[repeat], levels[repeat] = now, severity
    if extra:
        messages.append(dict(message("syslog", "warning", f"{len(extra)} more log messages", "\n".join(extra)),
                             note=True))
    if "\tnot checked" not in seen:
        found_note = left_out("syslog", "log messages", missed, skipped)
        if found_note:
            seen["\tnot checked"] = now
        messages += found_note
    # bounded against floods of differing lines
    if len(seen) > SEEN_MAX:
        seen = dict(sorted(seen.items(), key=lambda kv: kv[1])[-SEEN_MAX:])
    return {"files": files, "seen": seen, "levels": {k: v for k, v in levels.items() if k in seen}}, messages


def check_device(config, previous):
    now = int(time.time())
    if previous is not None and now - previous.get("checked", 0) < DEVICE_INTERVAL:
        return previous, []
    hosts = configctl_json("hostwatch", "dump_full")
    if not isinstance(hosts, dict):
        return previous, []
    names = config.get("interfaces", {})
    known = list((previous or {}).get("macs", []))
    seen = set(known)
    found: dict = {}  # a row per address of each new device
    for row in hosts.get("rows", []):
        if len(row) >= 3 and row[1] and row[1].lower() not in seen:
            found.setdefault(row[1].lower(), []).append(row)
    messages = []
    for mac, rows in found.items():
        known.append(mac)
        if previous is None:
            continue  # first pass records what is already there
        # the address it is best found by: IPv4, then global IPv6, then link-local
        row = min(rows, key=lambda r: (not r[2], ":" in str(r[2]), str(r[2]).lower().startswith("fe80:")))
        vendor = next((r[3] for r in rows if len(r) > 3 and r[3]), "")
        device = f"{mac} ({vendor})" if vendor else mac
        messages.append(message("device", "info", f"New device on {names.get(row[0], row[0])}: {device} at {row[2]}",
                                f"{mac} ({vendor or 'unknown vendor'}) at {row[2]}"))
    return {"checked": now, "macs": known[-DEVICES_MAX:]}, messages


def check_ids(config, previous):
    severity = setting(config["general"], "idsSeverity", 1)
    lines, state, (missed, skipped) = follow(IDS_LOG, previous or {}, keep=b'"event_type":"alert"')
    messages = left_out("ids", "IDS alerts", missed, skipped)
    for line in lines:
        try:
            event = json.loads(line)
        except ValueError:
            continue
        alert = event.get("alert") if isinstance(event, dict) and event.get("event_type") == "alert" else None
        try:
            if not isinstance(alert, dict) or int(alert.get("severity", 3)) > severity:
                continue
        except (TypeError, ValueError):
            continue  # else it stalls the log
        where = f"{event.get('src_ip', '?')} -> {event.get('dest_ip', '?')}"
        messages.append(message("ids", "warning", alert.get("signature", "IDS alert"),
                                f"{where}\nSeverity {alert.get('severity')}, {alert.get('category', '')}",
                                {"signature": alert.get("signature", ""), "source": event.get("src_ip", "")}))
    return state, messages


def check_carp(config, previous):
    names = config.get("interfaces", {})
    current, messages = {}, []
    for device, vhid, state in carp_vhids():
        key = f"{vhid}@{device}"
        current[key] = state
        last = (previous or {}).get(key)
        if previous is None or last is None or last == current[key]:
            continue
        ntype = "info" if current[key] == "MASTER" else "warning"
        title = f"CARP vhid {vhid} on {names.get(device, device)} is now {current[key]}"
        messages.append(message("carp", ntype, title, f"Changed from {last}."))
    return current, messages


def check_wanip(config, previous):
    """Addresses on the uplinks, so a dynamic address change is reported."""
    names, current, messages = config.get("interfaces", {}), {}, []
    held = addresses()
    for device in config.get("uplinks", []):
        current[device] = ", ".join(sorted(held.get(device, [])))
        last = (previous or {}).get(device)
        if previous is None or last is None or last == current[device] or not current[device]:
            continue
        name = names.get(device, device)
        messages.append(message("wanip", "info", f"{name} address is now {current[device]}",
                                f"Was {last or 'unset'}."))
    return current, messages


def check_link(config, previous):
    """Carrier on the configured interfaces."""
    names, current, messages = config.get("interfaces", {}), {}, []
    for device, status in link_states(names).items():
        current[device] = status
        last = (previous or {}).get(device)
        if previous is None or last is None or last == current[device]:
            continue
        up = current[device] in LINK_UP
        messages.append(message("link", "success" if up else "failure",
                                f"{names[device]} link is {current[device]}", f"Was {last}."))
    return current, messages


def check_states(config, previous):
    """The firewall state table against its limit."""
    threshold = setting(config["general"], "statesPercent", 80)
    found = pf_states()
    if found is None or not found[1]:
        return previous, []  # no limit to measure against, e.g. "states unlimited"
    entries, limit = found
    percent = entries * 100 // max(limit, 1)
    current = {"over": percent >= threshold}
    if previous is None or previous.get("over") == current["over"]:
        return current, []
    detail = f"{entries} of {limit} states ({percent}%)."
    if current["over"]:
        return current, [message("states", "warning", "Firewall state table is filling up", detail)]
    return current, [message("states", "success", "Firewall state table is back to normal", detail)]


def ups_status(config):
    """(name, state, detail) per UPS, from the apcupsd or NUT plugin, as its own status page asks."""
    found = []
    ups = config.get("ups") or {}
    if ups.get("apcupsd"):
        output = configctl("apcupsd", "upsstatus") or ""
        values = dict(line.split(":", 1) for line in output.splitlines() if ":" in line)
        values = {k.strip().upper(): v.strip() for k, v in values.items()}
        if values.get("STATUS"):
            detail = ", ".join(filter(None, [
                f"battery {values['BCHARGE']}" if values.get("BCHARGE") else "",
                f"{values['TIMELEFT']} left" if values.get("TIMELEFT") else "",
                f"input {values['LINEV']}" if values.get("LINEV") else "",
            ]))
            found.append((values.get("UPSNAME") or "UPS", values["STATUS"].lower(), detail))
    if ups.get("nut"):
        # name@host, as NUT's own status page asks
        output = configctl("nut", "upsstatus", str(ups["nut"])) or ""
        values = dict(line.split(":", 1) for line in output.splitlines() if ":" in line)
        values = {k.strip(): v.strip() for k, v in values.items()}
        flags = [UPS_FLAGS.get(f, f) for f in values.get("ups.status", "").split()]
        if flags:
            detail = ", ".join(filter(None, [
                f"battery {values['battery.charge']}%" if values.get("battery.charge") else "",
                f"{int(values['battery.runtime']) // 60} min left"
                if values.get("battery.runtime", "").isdigit() else "",
            ]))
            found.append((str(ups["nut"]).partition("@")[0], " ".join(flags), detail))
    return found


def check_ups(config, previous):
    """Power state from apcupsd or NUT, when either is installed."""
    # one not read, e.g. its daemon restarting, keeps its state, so its change still shows
    current, messages = dict(previous or {}), []
    for name, state, detail in ups_status(config):
        current[name] = state
        last = (previous or {}).get(name)
        if previous is None or last is None or last == state:
            continue
        good = any(hint in state for hint in ("online", "on line"))
        low = any(hint in state for hint in UPS_FAULTS)
        was_low = any(hint in last for hint in UPS_FAULTS)
        ntype = "failure" if low and not was_low else ("success" if good and not low else "warning")
        messages.append(message("ups", ntype,
                                f"UPS {name} is {state}", " ".join(filter(None, [detail, f"Was {last}."]))))
    return current, messages


COLLECTORS = (
    ("gateway", check_gateway),
    ("config", check_config),
    ("auth", check_auth),
    ("vpn", check_vpn),
    ("device", check_device),
    ("ids", check_ids),
    ("firmware", check_firmware),
    ("certificate", check_certificate),
    ("monit", check_monit),
    ("service", check_service),
    ("status", check_status),
    ("carp", check_carp),
    ("wanip", check_wanip),
    ("link", check_link),
    ("states", check_states),
    ("ups", check_ups),
    ("syslog", check_syslog),
)


# ------------------------------------------------------------------ delivery


def plugin_classes(schema):
    """Class names of the service behind a schema, its bases included."""
    from apprise.plugins import N_MGR
    return class_names(N_MGR[schema]) if schema in N_MGR else set()


def usable(schema):
    """Whether the service behind a schema has a module it needs (NEEDS_ONE_OF)."""
    import importlib.util
    return all(any(importlib.util.find_spec(m) for m in modules)
               for name, modules in NEEDS_ONE_OF.items() if name in plugin_classes(schema))


def class_names(cls):
    """Names of a plugin class and its bases, as the tables here name services."""
    return {c.__name__ for c in cls.__mro__}


def file_args(schema):
    """The URL arguments the service behind a schema opens as files."""
    names = plugin_classes(schema)
    return {arg for name, args in FILE_ARGS.items() if name in names for arg in args}


def apprise_view(url):
    """(file arguments of its service, {argument: value}) of what Apprise builds a plugin from:
    its own url_to_dict, as Apprise.instantiate runs it, so the service is the one it resolves,
    a native https:// webhook included, and the values are the ones the plugin reads. The checks
    look at this, never at a reading of their own. ({}, {}) when Apprise cannot read the URL."""
    results = apprise_results(url)
    if results is None:
        return set(), {}
    return file_args(results["schema"]), dict(results.get("qsd") or {})


def apprise_results(url):
    """What Apprise's url_to_dict makes of a URL, or None; a plugin tripping over it is None too."""
    from apprise.plugins import N_MGR, url_to_dict
    try:
        results = url_to_dict(url) if isinstance(url, str) and url else None
    except Exception:
        return None
    return results if isinstance(results, dict) and results.get("schema") in N_MGR else None


def local_file_args(url):
    """The arguments of a URL that would make Apprise read a file this plugin did not write, or
    fetch a private key from elsewhere; an empty one names nothing, and Apprise ignores it."""
    args, values = apprise_view(url)
    return [key for key, value in values.items() if key in args and value not in ("", KEY_MARKER)
            and not (key in REMOTE_FILE_ARGS and re.match(r"https://", value, re.I))]


def plain_http_args(url, names):
    """Those of names that are fetched but given as http://; only https is fetched."""
    _, values = apprise_view(url)
    return [key for key in names if key.lower() in REMOTE_FILE_ARGS
            and values.get(key.lower(), "").lower().startswith("http://")]


def file_label(schema, arg):
    """(label, hint) for a file argument, or None."""
    names = plugin_classes(schema)
    for (name, key), label in FILE_LABELS.items():
        if key == arg and (name is None or name in names):
            return label
    return None


def stored_file_args(url):
    """The arguments of a URL whose file the channel stores."""
    args, values = apprise_view(url)
    return [key for key, value in values.items() if key in args and value == KEY_MARKER]


def with_key_files(channel):
    """The channel URL with each stored file written out and its marker replaced by the path, and
    each remote file set to be fetched over verified https only."""
    url, files = channel.get("url", ""), channel.get("files") or {}
    args, _ = apprise_view(url)
    base, sep, query = url.partition("?")
    pairs = query_pairs(query) if sep else []
    # a repeated file argument counts only where Apprise takes it, its last, so the others go
    last = {name: i for i, (_, name, _) in enumerate(pairs) if name in args}
    parts = []
    written = {}
    fetched = {}
    for i, (text, name, value) in enumerate(pairs):
        if name in args and last[name] != i:
            continue
        if name in args and name in REMOTE_FILE_ARGS and re.match(r"https://", value, re.I):
            fetched[name] = fetch_as_allowed(value)
            text = f"{name}={urllib.parse.quote(fetched[name], safe='')}"
        elif name in args and value == KEY_MARKER:
            content = files.get(name)
            if not isinstance(content, str) or content == "":
                raise ValueError(f"The file for {name} is not stored with this channel; paste it again.")
            if not CHANNEL_ID.fullmatch(channel["uuid"]):
                raise ValueError("The channel's ID is not valid.")
            written[name] = os.path.join(KEY_DIR, f"{channel['uuid']}-{name}")
            write_private(written[name], content, only_changed=True)
            text = f"{name}={urllib.parse.quote(written[name], safe='')}"
        parts.append(text)
    result = base + (sep + "&".join(parts) if sep else "")
    # what Apprise builds from it: each stored file's argument names the file written for it, and
    # no marker is left that this reading missed
    _, found = apprise_view(result)
    if any(found.get(name) != path for name, path in {**written, **fetched}.items()) \
            or any(found.get(name) == KEY_MARKER for name in args):
        raise ValueError("The URL's stored files could not be put in place; save the channel again.")
    return result


def fetch_as_allowed(url):
    """A remote file's own URL, set to be fetched only over verified https: Apprise would otherwise
    follow a redirect, which can lead to plain http, or skip the check with verify=no. What the URL
    says of either is replaced."""
    base, _, query = url.partition("?")
    kept = [text for text, key, _ in query_pairs(query) if key not in ("redirect", "verify")]
    return base + "?" + "&".join(kept + ["verify=yes", "redirect=no"])


def prune_key_files(channels):
    """Remove the key files of channels, or arguments, that no longer use them. A channel lists the
    files its URL names, so Apprise's services are not loaded for this."""
    try:
        names = os.listdir(KEY_DIR)
    except OSError:
        return
    wanted = {f"{c['uuid']}-{key}" for c in channels if KEY_MARKER in urllib.parse.unquote(c.get("url", ""))
              for key in (c.get("files") or {})}
    for name in names:
        if name not in wanted and not (name.endswith(".tmp") and not stale_tmp(os.path.join(KEY_DIR, name))):
            try:
                os.unlink(os.path.join(KEY_DIR, name))
            except OSError:
                pass


def deliver(channel, title, body, ntype, report=None):
    """Send one notification: (ok, error). It never raises: an odd URL or a fault in Apprise
    fails this delivery alone, which is retried, rather than the whole check."""
    try:
        ok, said = deliver_once(channel, title, body, ntype, report)
    except Exception as exc:
        # its type and where, not its text, which in Apprise or requests can carry the URL's secrets
        frame = traceback.extract_tb(exc.__traceback__)[-1] if exc.__traceback__ else None
        where = f" at {os.path.basename(frame.filename)}:{frame.lineno}" if frame else ""
        log(syslog.LOG_ERR, f"delivery tripped: {type(exc).__name__}{where}")
        return False, f"Delivery failed ({type(exc).__name__})."
    # what Apprise says can carry the URL's secrets, e.g. a webhook's address in a connection error;
    # what cannot be masked is not said, and a send that went stays sent
    try:
        return ok, masked(said, url_secrets(channel.get("url", ""))) if said else said
    except Exception:
        return ok, "" if ok else "Delivery failed."


def deliver_once(channel, title, body, ntype, report=None):
    """A summary goes to email as HTML with inline graphs, elsewhere as its short text with a
    link to the report."""
    try:
        import apprise
    except ImportError as exc:
        return False, f"The bundled Apprise could not be loaded: {exc}"
    error = refused(channel.get("url", ""))  # a channel saved before its URL was refused is not sent to
    if error:
        return False, error
    try:
        url = with_key_files(channel)
    except (ValueError, OSError) as exc:
        return False, str(exc)
    refused_by_server: list = []
    with apprise_log() as captured, partly_sent(refused_by_server):
        # the one plugin the checks looked at (add() would split the string at commas), waited for
        # as Apprise 1.13 did: a send given up on can still arrive, and would be sent again; named
        # Notify where a service names the sender, e.g. a Discord embed's author, not Apprise
        asset = apprise.AppriseAsset(service_timeout=0, app_id="Notify", app_desc="OPNsense Notify")
        plugin, error = one_plugin(url, asset=asset)
        notifier = apprise.Apprise()
        if plugin is None or not notifier.add(plugin):
            return False, error or "The URL is not a valid Apprise URL."
        plugin.optional = False  # a failure must reach the queue, not count as sent
        if "NotifyDiscord" in class_names(type(plugin)):
            title, body = quiet(title), quiet(body)
        email = report and full_report(plugin)
        page, drawn = None, {}
        if email:
            try:
                drawn = report_graphs(report)
                page = report_page(report, drawn, embed=False)  # a whole document, for its style sheet
            except Exception as exc:  # e.g. /tmp full: send the short text
                log(syslog.LOG_ERR, f"summary report could not be prepared, sending the short text: {exc}")
        if page is not None:
            plugin.inline = True  # graphs in their sections, not listed at the end
            ok = bool(notifier.notify(body=page, title=title, notify_type=ntype,
                                      body_format=apprise.NotifyFormat.HTML,
                                      attach=[graph["path"] for graph in drawn.values()] or None))
        else:
            title, body, given = with_link(plugin, title, body, (report or {}).get("link"))
            if "overflow" not in url_args(url) and 0 < plugin.body_maxlen < len(title) + len(body):
                # over a service's limit it is refused: split a summary, cut the rest. Only then, as
                # Apprise sizes some services anew for each send, e.g. Matrix, and can cut short there
                plugin.overflow_mode = apprise.OverflowMode.SPLIT if report else apprise.OverflowMode.TRUNCATE
            ok = bool(notifier.notify(body=body, title=title, notify_type=ntype, body_format=given))
    if ok and refused_by_server:
        return ok, f"The mail server refused {', '.join(sorted(set(refused_by_server)))}."
    return ok, "" if ok else last_warning(captured, "Delivery failed.")


def with_link(server, title, body, link):
    """(title, body, format) of the short text, with the report's link last as a link in the format
    the service renders. The text carries outsiders' input, e.g. a failed login's user name, so
    it goes as text, which Apprise escapes for Markdown or HTML, a link in it too; with a link it
    is prepared here as Apprise.notify prepares it, emojis and then conversion."""
    import apprise
    from apprise.conversion import convert_between
    from apprise.emojis import apply_emojis
    text = apprise.NotifyFormat.TEXT
    rendered = server.resolve_format(text) if link else text
    if rendered == apprise.NotifyFormat.MARKDOWN:
        # Telegram's legacy Markdown would show a URL's escapes in the link's text
        anchor = "[Full report](%s)" % re.sub(r"[\s()]", lambda m: urllib.parse.quote(m.group()), link)
    elif rendered == apprise.NotifyFormat.HTML:
        # the URL shown too, as a service may send HTML as text, e.g. Matrix to Slack
        anchor = 'Full report: <a href="{0}">{0}</a>'.format(html.escape(link))
    elif link:
        # bracketed: Apprise's Discord can append a ping right after the body
        return title, f"{body}\nFull report: <{link}>", text
    else:
        return title, body, text

    def prepared(content):
        return convert_between(text, rendered, apply_emojis(content) if server.interpret_emojis else content)
    # a title Apprise blends into the body is converted with it
    return prepared(title) if title and server.title_maxlen <= 0 else title, prepared(body + "\n") + anchor, rendered


@contextlib.contextmanager
def partly_sent(refused):
    """As with Apprise 1.13, a message the mail server took for some of its recipients is sent, so a
    retry does not reach them again; those it refused are collected with its reply. Apprise sends
    a message per To address, with any Cc and Bcc: one refused outright still fails the send."""
    from apprise.plugins.email import smtp
    original = smtp.AppriseSMTPController.sendmail

    def sendmail(self, from_addr, to_addrs, message):
        # Apprise's own, with the refusals smtplib returns recorded (it raises when all are refused),
        # and Apprise's warnings about them held back, as they are no reason for a failed send
        missed: dict = {}
        socket_sendmail = self._socket.sendmail

        def recorded(*args, **kwargs):
            missed.update(socket_sendmail(*args, **kwargs) or {})
            return missed

        def held(record):
            return not (isinstance(record.args, tuple) and record.args and record.args[0] in missed)
        self._socket.sendmail = recorded
        smtp.logger.addFilter(held)
        try:
            sent = original(self, from_addr, to_addrs, message)
        finally:
            del self._socket.sendmail
            smtp.logger.removeFilter(held)
        refused.extend(f"{addr} ({code} {reply.decode(errors='replace') if isinstance(reply, bytes) else reply})"
                       for addr, (code, reply) in missed.items())
        return sent or bool(missed)

    smtp.AppriseSMTPController.sendmail = sendmail
    try:
        yield
    finally:
        smtp.AppriseSMTPController.sendmail = original


def report_email(cls):
    """Whether a plugin class is email that takes HTML, so a summary can go as the full report."""
    import apprise
    formats = getattr(cls, "notify_format", ())
    formats = formats if isinstance(formats, (tuple, list)) else (formats,)
    return "NotifyEmail" in class_names(cls) and apprise.NotifyFormat.HTML in formats


def full_report(plugin):
    """Whether a plugin is email that sends HTML, so a summary goes as the full report."""
    import apprise
    return report_email(type(plugin)) and plugin.resolve_format(apprise.NotifyFormat.HTML) == apprise.NotifyFormat.HTML


def text_email(plugin):
    """Whether email that could take the full report is kept to text by format=text."""
    import apprise
    return plugin is not None and report_email(type(plugin)) \
        and plugin.resolve_format(apprise.NotifyFormat.HTML) != apprise.NotifyFormat.HTML


def apprise_log():
    """A capture of what Apprise warns of, read with logged()."""
    import apprise
    return apprise.LogCapture(level=apprise.logging.WARNING, fmt="%(message)s" + LOG_MARK)


def logged(captured):
    """The messages captured, each whole and trimmed."""
    return [text.strip() for text in captured.getvalue().split(LOG_MARK) if text.strip()]


def last_warning(captured, fallback):
    """The first line of what Apprise last warned of, which says why it failed; a server's reply
    can follow it."""
    messages = logged(captured)
    return messages[-1].splitlines()[0] if messages else fallback


def title_prefix(general, hostname):
    """What goes in front of every title: the host name, custom text or nothing."""
    setting = general.get("titlePrefix", "hostname")
    if setting == "none":
        return ""
    if setting == "custom":
        return general.get("titleText", "").strip()
    return hostname


def wants(channel, item):
    if item.get("quiet"):
        return False  # counted in summaries, not sent
    if item["event"] == "summary":
        return bool(summary_channels([channel]))  # not once the channel's summary is switched off
    if item["event"] == "digest":
        # a queued one needs one of its events still taken
        return "events" not in item or any(event in channel["events"] for event in item["events"])
    return item["event"] in channel["events"] and monit_allowed(channel, item)


def digest(items, threshold):
    """Fold a burst for one channel into a single notification."""
    if threshold < 1 or len(items) < threshold:
        return items
    # titles while they fit a small service, then the count
    lines: list = []
    for item in items[:DIGEST_LINES]:
        line = f"- {item['title']}"
        if sum(len(x) + 1 for x in lines) + len(line) > DIGEST_CHARS:
            break
        lines.append(line)
    if len(items) > len(lines):
        lines.append(f"- and {len(items) - len(lines)} more")
    types = [item["type"] for item in items]
    kind = "failure" if "failure" in types else ("warning" if "warning" in types else "info")
    summary = message("digest", kind, f"{len(items)} notifications", "\n".join(lines))
    return [dict(summary, uuid=items[0]["uuid"], events=sorted({item["event"] for item in items}))]


def discard(item):
    """Remove the archived page of a summary that was not sent."""
    if item.get("archive"):
        remove_report(item["archive"])


def send(channels, prefix, messages, queue, threshold=0):
    now = int(time.time())
    pending = []
    fresh = []
    for channel in channels:
        wanted = [dict(m, uuid=channel["uuid"]) for m in messages if wants(channel, m)]
        fresh.extend(digest(wanted, threshold))
    for item in queue + fresh:
        channel = next((c for c in channels if c["uuid"] == item.get("uuid")), None)
        name = channel.get("description", item.get("uuid", "")) if channel else ""
        if channel is None:
            discard(item)  # disabled or deleted
            continue
        if not wants(channel, item):
            discard(item)
            continue
        if now - item["time"] > RETRY_SECONDS:
            log(syslog.LOG_ERR, f"gave up on \"{item['title']}\" for {name} after "
                                f"{duration(now - item['time'])}")
            discard(item)
            continue
        if now < item.get("retry", 0) - CHECK_SLACK:
            pending.append(item)  # waiting out the backoff
            continue
        title = f"{prefix}: {item['title']}" if prefix else item["title"]
        body, report = item["body"], item.get("report")
        if now - item["time"] > 90:
            late = f"(Delayed: this happened at {clock(item['time'])}.)"
            body += f"\n\n{late}"
            report = dict(report, delayed=late) if report else report
        ok, error = deliver(channel, title, body, item["type"], report)
        if ok:
            log(syslog.LOG_NOTICE, f"sent \"{item['title']}\" to {name}")
            if error:
                log(syslog.LOG_WARNING, f"\"{item['title']}\" to {name}: {error}")
            continue
        tries = item.get("tries", 0) + 1
        delay = RETRY_DELAYS[min(tries, len(RETRY_DELAYS)) - 1]
        item.update(tries=tries, retry=now + delay)
        log(syslog.LOG_ERR, f"could not send \"{item['title']}\" to {name}, "
                            f"retrying in {duration(delay)}: {error}")
        pending.append(item)
    if len(pending) > QUEUE_MAX:
        log(syslog.LOG_ERR, f"dropped the {len(pending) - QUEUE_MAX} oldest queued notification(s), "
                            f"over the limit of {QUEUE_MAX}")
        for item in pending[:-QUEUE_MAX]:
            discard(item)
    return pending[-QUEUE_MAX:]


def prepare(config=None):
    """Settings and enabled channels, or None when switched off or unreadable."""
    config = load_config() if config is None else config
    if config is None:
        return None
    general = config["general"]
    if general.get("enabled", "0") != "1":
        return None
    channels = [c for c in config["channels"] if c.get("enabled", "0") == "1"]
    return config, general, channels, config["hostname"]


def run_check():
    config = load_config()
    if config is None:
        return  # unreadable, which says nothing about whether Notify is on: keep the state
    prepared = prepare(config)
    if prepared is None:
        # disabled: start from a fresh baseline when enabled again; what was queued is never sent
        for item in load_state().get("queue", []):
            discard(item)
        if os.path.exists(STATE):
            os.remove(STATE)
        return
    config, general, channels, hostname = prepared
    if interfaces() is None:
        # links, addresses and CARP would read as gone
        log(syslog.LOG_ERR, "interfaces could not be read; check skipped")
        return
    prune_key_files(config["channels"])
    prune_stale(os.path.dirname(STATE))
    events = subscribed(channels)
    state = fresh_state()
    now = int(time.time())
    new_state: dict = {"stamp": now, "channel_ids": sorted(c["uuid"] for c in config["channels"])}
    if "channel_ids" in state:
        # gone from two reads in a row, so not a list read half made
        prune_archive(set(new_state["channel_ids"]) | set(state["channel_ids"]))
    messages: list = []
    for event, collector in COLLECTORS:
        if event not in events:
            continue  # dropped, so subscribing later starts from a baseline
        try:
            new_state[event], found = collector(config, state.get(event))
        except Exception as exc:
            log(syslog.LOG_ERR, f"{event} check failed: {exc!r}")
            new_state[event], found = state.get(event), []
        messages.extend(found)
    if is_carp_backup(config):
        # standby: the master reports; counters still sampled for the baseline
        new_state["queue"] = state.get("queue", [])
        kept = state.get("summary") or {}
        periods = standby_periods(config, channels, kept, now)
        new_state["summary"] = dict(kept, channels=periods)
        if now - kept.get("sampled", 0) >= SAMPLE_SECONDS:  # as often as a master reads them
            try:
                # baseline only
                summary, _ = update_summaries(config, channels, dict(kept, channels={}), [], now)
                new_state["summary"] = dict(summary, channels=periods) if summary else {}
            except Exception as exc:
                log(syslog.LOG_ERR, f"summary failed: {exc}")
        save_state(new_state)
        return
    threshold = setting(general, "digestFrom", 0)
    try:
        summary, due = update_summaries(config, channels, state.get("summary"), messages, now)
    except Exception as exc:
        log(syslog.LOG_ERR, f"summary failed: {exc}")
        summary, due = state.get("summary", {}), []
    summaries: list = []
    shared: dict = {}
    for channel, period in due:
        try:
            summaries.append(archived(config, build_summary(config, channel, period, now, shared),
                                      period.get("schedule", channel["summary"]), now))
        except Exception as exc:
            name = channel.get("description", channel["uuid"])
            tries = period.get("tries", 0) + 1
            if tries >= SUMMARY_TRIES:
                log(syslog.LOG_ERR, f"summary for {name} failed {tries} times, dropped: {exc}")
                continue
            log(syslog.LOG_ERR, f"summary for {name} failed, trying again next check: {exc}")
            summary["channels"][channel["uuid"]] = dict(period, tries=tries)
    new_state["summary"] = summary
    # sent before the state is saved: a run that dies in between sends again rather than loses
    new_state["queue"] = send(channels, title_prefix(general, hostname), messages,
                              state.get("queue", []) + summaries, threshold)
    save_state(new_state)


def run_boot():
    prepared = prepare()
    if prepared is None:
        return
    config, general, channels, hostname = prepared
    if is_carp_backup(config, unknown=False):  # a startup notice twice beats none
        return
    state = fresh_state()
    (state.get("service") or {}).pop("uptime", None)  # a boot is never continuous with the check before it
    version = str(firmware_product().get("product_version") or "").strip()
    body = f"Running OPNsense {version}." if version else ""
    found = [message("boot", "info", "Firewall has started", body)]
    periods = (state.get("summary") or {}).get("channels") or {}
    for channel in summary_channels(channels):
        if channel["uuid"] in periods:
            periods[channel["uuid"]] = add_events(periods[channel["uuid"]], channel, found, latest(general))
    state["queue"] = send(channels, title_prefix(general, hostname), found, state.get("queue", []))
    state["stamp"] = int(time.time())
    save_state(state)


def run_status():
    config = load_config() or {"general": {}, "channels": []}
    general, channels = config["general"], config["channels"]
    names = {c["uuid"]: c.get("description", c["uuid"]) for c in channels}
    state = load_state()
    now = int(time.time())
    enabled = [c for c in channels if c.get("enabled", "0") == "1"]
    live = {c["uuid"] for c in enabled}
    # not those of a channel deleted or disabled since, which the next check drops; one due is taken
    # by the next check, as send() takes it
    queued = [{
        "title": item.get("title", ""),
        "channel": names[item["uuid"]],
        "event": item.get("event", ""),
        "age": duration(now - item.get("time", now)),
        "tries": item.get("tries", 0),
        "retry_in": duration(item["retry"] - now) if item.get("retry", 0) - CHECK_SLACK > now else "at the next check",
    } for item in state.get("queue", []) if item.get("uuid") in live]
    try:
        # saved before a channel took one URL, so not sent to
        split = [c.get("description", c["uuid"]) for c in enabled if several_urls(c.get("url", ""))]
    except ImportError:
        split = []  # the status still reads without Apprise
    labels = config.get("eventLabels") or {}
    return {
        "enabled": general.get("enabled", "0") == "1",
        "checked": clock(state["stamp"]) if state.get("stamp") else "",
        "age": duration(now - state["stamp"]) if state.get("stamp") else "",
        "channels": len(enabled),
        "events": sorted(labels.get(event, event) for event in subscribed(enabled)),
        "queued": queued,
        "split": split,
    }


def with_lock(seconds, func):
    """func() holding the check lock, waited for up to this long; None while a check still holds
    it, so the caller can say so instead of answering nothing."""
    import fcntl
    with open(LOCK, "a") as handle:
        deadline = time.monotonic() + seconds
        while True:
            try:
                fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                if time.monotonic() > deadline:
                    return None
                time.sleep(0.5)
                continue
            return func()


def run_test(uuid):
    config = load_config()
    if config is None:
        return {"status": "failed", "message": "The settings could not be read."}
    general, channels, hostname = config["general"], config["channels"], config["hostname"]
    channel = next((c for c in channels if c["uuid"] == uuid), None)
    if channel is None:
        return {"status": "failed", "message": "Save the channel before testing it."}
    prefix = title_prefix(general, hostname)
    ok, error = deliver(channel, f"{prefix}: Test notification" if prefix else "Test notification",
                        "This is a test notification from OPNsense.", "info")
    name = channel.get("description", uuid)
    if ok:
        log(syslog.LOG_NOTICE, f"sent test notification to {name}")
        if error:
            log(syslog.LOG_WARNING, f"test notification to {name}: {error}")
        return {"status": "ok", "message": error} if error else {"status": "ok"}
    log(syslog.LOG_ERR, f"could not send test notification to {name}: {error}")
    return {"status": "failed", "message": error}


def archived(config, item, schedule, when, manual=False):
    """The summary item, archived, with a link to its page that delivery adds to the short text."""
    try:
        name = archive_report(item["report"], item["uuid"], schedule, when, manual)
    except Exception as exc:  # it is still sent
        log(syslog.LOG_ERR, f"\"{item['title']}\" not archived: {exc}")
        return item
    base = (config["general"].get("reportAddress") or config.get("guiUrl") or "").rstrip("/")
    if not base:
        return dict(item, archive=name)
    return dict(item, archive=name, report=dict(item["report"], link=f"{base}/ui/notify/report/view/{name}"))


def run_reports():
    """Archived summaries, newest first."""
    config = load_config() or {"channels": []}
    names = {c["uuid"]: c.get("description", "") for c in config["channels"]}
    return [{"name": r["name"], "channel": names.get(r["channel"], r["channel"]),
             "schedule": r["schedule"].capitalize() + (" (so far)" if r["manual"] else ""), "when": clock(r["when"])}
            for r in sorted(archived_reports(), key=lambda r: -r["when"])]


def run_report(name):
    """An archived summary's page, base64; only archive names are accepted."""
    if not REPORT_NAME.fullmatch(name or ""):
        return {"status": "failed"}
    try:
        with open(os.path.join(REPORTS_DIR, name), "rb") as handle:
            return {"status": "ok", "payload": base64.b64encode(handle.read()).decode()}
    except OSError:
        return {"status": "failed"}


def run_delete(name):
    """Delete an archived summary; only archive names are accepted."""
    if not REPORT_NAME.fullmatch(name or ""):
        return {"status": "failed"}
    remove_report(name)
    return {"status": "failed" if os.path.exists(os.path.join(REPORTS_DIR, name)) else "ok"}


def run_summary(uuid):
    """Send a channel's summary of its period so far, leaving the period running."""
    config = load_config()
    if config is None:
        return {"status": "failed", "message": "The settings could not be read."}
    channel = next((c for c in config["channels"] if c["uuid"] == uuid), None)
    if channel is None or channel.get("summary", "none") == "none":
        return {"status": "failed", "message": "This channel has no summary."}
    if config["general"].get("enabled", "0") != "1" or channel.get("enabled", "0") != "1":
        return {"status": "failed", "message": "Enable Notify and this channel first."}
    if interfaces() is None:
        return {"status": "failed", "message": "The interfaces could not be read; try again."}
    if is_carp_backup(config):
        return {"status": "failed", "message": "This firewall is the CARP standby; the master sends summaries."}
    state = load_state()
    period = (state.get("summary", {}).get("channels") or {}).get(uuid)
    if period is None:
        return {"status": "failed", "message": "No summary period recorded yet; wait for the next check."}
    if period.get("schedule") != channel["summary"]:
        return {"status": "failed", "message": "The schedule has changed; its new period starts at the next check."}
    interval = setting(config["general"], "interval", 1) * 60
    if int(time.time()) - state.get("stamp", 0) > 2 * interval + 120:
        return {"status": "failed", "message": "Checks have stopped running, so the figures would be out of date."}
    name = channel.get("description", uuid)
    item: dict = {}
    try:
        now = int(time.time())
        item = build_summary(config, channel, period, now)
        title = f"{item['title']} so far"  # before archiving, so the page says so too
        item = archived(config, dict(item, title=title, report=dict(item["report"], title=title)),
                        period["schedule"], now, manual=True)
        prefix = title_prefix(config["general"], config["hostname"])
        ok, error = deliver(channel, f"{prefix}: {title}" if prefix else title, item["body"], "info", item["report"])
    except Exception as exc:
        ok, error = False, f"The summary could not be sent: {exc}"
    if ok:
        log(syslog.LOG_NOTICE, f"sent summary so far to {name}")
        if error:
            log(syslog.LOG_WARNING, f"summary so far to {name}: {error}")
        return {"status": "ok", "message": error} if error else {"status": "ok"}
    discard(item)
    log(syslog.LOG_ERR, f"could not send summary so far to {name}: {error}")
    return {"status": "failed", "message": error}


# ------------------------------------------------------------------ channel URLs
# the settings page builds a channel URL from fields generated out of Apprise's own
# service details, so new or changed services need no plugin changes


@functools.lru_cache(maxsize=1)
def apprise_services():
    """Apprise services keyed by id, with a lookup from every schema to the id; built once, never
    changed by callers."""
    import apprise
    services: dict = {}
    schemas: dict = {}
    for entry in apprise.Apprise().details()["schemas"]:
        protocols = list(entry.get("secure_protocols") or []) + list(entry.get("protocols") or [])
        templates = [str(t) for t in entry["details"]["templates"]]
        # a port is optional in a URL, though some forms are listed only with one, e.g. Fluxer's bot name
        templates += [t.replace(":{port}", "") for t in templates
                      if ":{port}" in t and t.replace(":{port}", "") not in templates]
        if not protocols or not templates or not usable(protocols[0]):
            continue
        keys: list[list[str]] = [re.findall(r"{(\w+)}", template) for template in templates]
        used = {key for form in keys for key in form}
        # what a service needs at minimum: its shortest URL form, anything Apprise marks
        # required, and where the notification goes; the rest are extras
        basic = set(sorted(keys, key=len)[0])
        tokens = {}
        hidden = {k for c in plugin_classes(protocols[0]) for k in PRIVATE_TOKENS.get(c, ())}
        # a token another name of which is private, e.g. Revolt's targets, read also as target_channel
        hidden |= {k for k, t in entry["details"]["tokens"].items()
                   if any(o.get("private") and o.get("map_to", n) == t.get("map_to", k)
                          for n, o in entry["details"]["tokens"].items())}
        for key, token in entry["details"]["tokens"].items():
            if key not in used:
                continue  # e.g. target_user, an alternative spelling of targets
            kind = str(token.get("type", "string"))
            field = {"key": key, "label": str(token.get("name", key)), "type": kind.split(":")[0],
                     "private": bool(token.get("private")) or key in hidden,
                     "basic": key in basic or str(token.get("required")) == "True"
                     or kind.startswith("list"),
                     "map_to": str(token.get("map_to", key))}
            if kind.startswith("choice"):
                field["values"] = [str(v) for v in token.get("values", ())]
            if "default" in token:
                field["default"] = str(token["default"])
            tokens[key] = field
        if "schema" in tokens:
            tokens["schema"]["basic"] = len(tokens["schema"].get("values") or protocols) > 1
            values = tokens["schema"].get("values") or protocols
            secure = [v for v in values if v in (entry.get("secure_protocols") or [])]
            tokens["schema"]["default"] = tokens["schema"].get("default") or (secure or values)[0]
        service_id = protocols[0]
        # several formats: the message's own is used unless one is chosen, from those it takes
        several = len(entry["details"]["args"].get("format", {}).get("supported") or ()) > 1
        args = {str(k): v.get("default") for k, v in entry["details"]["args"].items()
                if v.get("default") is not None and k not in UNSET_ARGS and not v.get("alias_of") and not (k == "format" and several)}
        mapped = {t["map_to"] for t in tokens.values()}
        options = {}
        for key, arg in entry["details"]["args"].items():
            if arg.get("alias_of") or key in tokens or str(arg.get("map_to", key)) in mapped:
                continue  # already a field
            kind = str(arg.get("type", "string"))
            field = {"key": str(key), "label": str(arg.get("name", key)), "type": kind.split(":")[0],
                     "private": bool(arg.get("private")), "basic": False, "map_to": str(arg.get("map_to", key))}
            # an optional secret is never shown again, so the dialog offers to remove it instead
            field["clearable"] = field["private"]
            if kind.startswith("choice"):
                # Apprise hands some over as a set; numbers sort as numbers
                field["values"] = sorted(
                    (str(v) for v in (arg["supported"] if key == "format" and several else arg.get("values", ()))),
                    key=lambda v: (not v.lstrip("-").isdigit(),
                                   int(v) if v.lstrip("-").isdigit() else v))
            if arg.get("default") is not None and not (key == "format" and several) and key not in UNSET_ARGS:
                field["default"] = default_text(arg["default"])
            if str(key).lower() in file_args(protocols[0]):
                # pasted into the dialog and stored with the channel, never shown again
                field.update(type="file", private=True)
                label = file_label(protocols[0], str(key).lower())
                if label:
                    field.update(label=label[0], hint=label[1])
            options[str(key)] = field
        # free-form arguments such as +header or -param, which can carry credentials
        prefixes = tuple(str(k["prefix"]) for k in (entry["details"].get("kwargs") or {}).values()
                         if k.get("prefix"))
        # query names that carry a secret no option field masks: a private token or argument given
        # by name, or an alias of one, e.g. Slack's and ntfy's token= or Exotel's key=
        private = {str(k) for k, t in entry["details"]["tokens"].items() if t.get("private") or k in hidden}
        private |= {str(k) for k, a in entry["details"]["args"].items() if a.get("private")}
        # Apprise reads ?user=, ?pass= and ?password= as credentials
        secrets = set(private) | {"user", "pass", "password"}
        for key, arg in entry["details"]["args"].items():
            alias = arg.get("alias_of")
            targets = alias if isinstance(alias, (tuple, list)) else (alias,) if alias else ()
            if arg.get("private") or any(str(t) in private for t in targets):
                secrets.add(str(key).lower())
        # query names a template fills itself, e.g. Nextcloud Talk's ?secret={secret}
        filled = {k.lower() for t in templates for k in re.findall(r"[?&](\w+)=\{", t)}
        services[service_id] = {"id": service_id, "name": str(entry["service_name"]),
                                "setup": str(entry.get("setup_url") or ""), "templates": templates,
                                "tokens": tokens, "args": args, "options": options, "prefixes": prefixes,
                                "secrets": secrets, "filled": filled}
        for protocol in protocols:
            schemas.setdefault(protocol.lower(), service_id)

    # options nearly every service has are Apprise's own, so they sort last; its per-send
    # retry, wait and optional are the exception, dropped because they would fight the queue
    shared: dict = {}
    for service in services.values():
        for key in service["options"]:
            shared[key] = shared.get(key, 0) + 1
    for service in services.values():
        for key in list(service["options"]):
            if key in ("retry", "wait", "optional"):
                del service["options"][key]
            else:
                service["options"][key]["common"] = shared[key] >= 0.9 * len(services)
    return services, schemas


def default_text(value):
    """An Apprise default as field text; some are enums, some bools."""
    value = getattr(value, "value", value)
    return ("yes" if value else "no") if isinstance(value, bool) else str(value)


def url_parts(url):
    """(schema, query) as Apprise reads a URL (its VALID_URL_RE): leading space and backslashes
    allowed, the query everything after the first ?, a # included. For the dialog's fields, which
    same_url holds to Apprise's reading; the checks read apprise_view."""
    from apprise.utils.parse import VALID_URL_RE
    match = VALID_URL_RE.search(url or "")
    if match is None:
        return "", ""
    return (match.group("schema") or "").lower().strip(), (match.group("kwargs") or "").strip()


def url_schema(url):
    return url_parts(url)[0]


def url_query(url):
    return url_parts(url)[1]


def custom_arg(text, prefixes):
    """Whether a query part is a free-form argument of one of the prefixes a service declares
    (+header, -param, :field), as Apprise's own patterns tell them apart; a leading space is +."""
    from apprise.utils.parse import (NOTIFY_CUSTOM_ADD_TOKENS, NOTIFY_CUSTOM_COLON_TOKENS,
                                     NOTIFY_CUSTOM_DEL_TOKENS)
    key = urllib.parse.unquote(text.partition("=")[0])
    patterns = {"+": NOTIFY_CUSTOM_ADD_TOKENS, "-": NOTIFY_CUSTOM_DEL_TOKENS, ":": NOTIFY_CUSTOM_COLON_TOKENS}
    return any(patterns[p].match(key) for p in prefixes if p in patterns)


def query_pairs(query):
    """[(text, key, value)] for each part of a query, split and read as Apprise's parse_qsd does:
    at & and ;, a + in a key after its first letter a space, decoded and trimmed, the key in
    lowercase. For rewriting a query; apprise_view says what it means."""
    from apprise.utils.parse import parse_qsd
    found = []
    for text in re.split(r"[&;]", query or ""):
        # each part read by parse_qsd itself, split where it splits
        for key, value in parse_qsd(text, simple=True)["qsd"].items() if text else []:
            found.append((text, key, value))
    return found


def url_args(url):
    """{argument: value} as Apprise reads a URL's query: split at & and ;, decoded and trimmed,
    keys in lowercase, the last of a repeated one kept."""
    from apprise.utils.parse import parse_qsd
    return parse_qsd(url_query(url))["qsd"]


def parse_saved(url, services, schemas):
    """(service id, {map_to: value}, query) for a saved URL, or (None, {}, "")."""
    service_id = schemas.get(url_schema(url))
    if service_id is None:
        return None, {}, ""
    results = apprise_results(url)
    query = url_query(url)
    return (service_id, results, query) if isinstance(results, dict) else (None, {}, "")


def saved_channel(uuid):
    if not uuid:
        return {}
    channels = (load_config() or {}).get("channels", [])
    return next((c for c in channels if c["uuid"] == uuid), None) or {}


def saved_url(uuid):
    return saved_channel(uuid).get("url", "")


def field_text(value):
    """A parsed URL value as field text; Apprise leaves e.g. passwords URL-encoded."""
    if isinstance(value, (list, tuple, set)):
        return ", ".join(urllib.parse.unquote(str(v)) for v in value)
    return "" if value is None else urllib.parse.unquote(str(value))


def saved_values(service, results, keys):
    """Field values for these token keys from a parsed saved URL."""
    values = {}
    for key in keys:
        token = service["tokens"][key]
        value = results.get(token["map_to"])
        if value not in (None, "", [], ()):
            values[key] = field_text(value)
    return values


def same_url(first, second):
    """Whether Apprise sets up two URLs the same; both were checked before, or composed here."""
    plugins = [one_plugin(url)[0] for url in (first, second)]
    return None not in plugins and plugins[0].url(privacy=False) == plugins[1].url(privacy=False)


def run_services():
    from apprise.plugins import N_MGR
    services, _ = apprise_services()
    result = []
    for service in sorted(services.values(), key=lambda s: s["name"].lower()):
        fields = sorted(service["tokens"].values(), key=lambda f: f["key"] != "schema")
        if len(fields) and fields[0]["key"] == "schema" and len(fields[0].get("values", [])) < 2:
            fields = fields[1:]  # nothing to choose
        fields += sorted(service["options"].values(), key=lambda f: (f["common"], f["label"].lower()))
        result.append({"id": service["id"], "name": service["name"], "setup": service["setup"],
                       "email": report_email(N_MGR[service["id"]]),
                       "fields": [{k: v for k, v in f.items() if k not in ("map_to", "common")}
                                  for f in fields]})
    return result


def run_describe(uuid):
    url = saved_url(uuid)
    described = describe_url(url)
    if url and text_email(check_url(url)[0]):
        described["textEmail"] = True
    return described


def same_value(value, default):
    """Does a URL parameter say the same as its default? A bool is read as Apprise reads it, e.g. t
    or on as yes, and anything else as the default."""
    from apprise.utils.parse import parse_bool
    value = str(value).strip().lower()
    if isinstance(default, bool):
        return parse_bool(value, default) == default
    return value == default_text(default).strip().lower()


def split_query(service, query):
    """A URL's query as (option field values, whatever no field covers), read as Apprise reads it."""
    values, rest = {}, []
    for text, key, value in query_pairs(query):
        if key in service["options"]:
            values[key] = value
        else:
            rest.append(text)
    return values, "&".join(rest)


def with_query(url, query):
    """The URL with a query added; a template may already hold one, e.g. ?secret={secret}."""
    return url + ("&" if "?" in url else "?") + query if query else url


def root_path(service):
    """Whether a Path of / is given as path=/, the only way the service takes the host root, e.g.
    Fluxer, whose empty path is /api/."""
    return service["tokens"].get("path", {}).get("default", "/") != "/"


def query_from(service, values, base=None):
    """The query for a service's option fields, leaving out anything at its default. Given the
    URL it goes on, a default is only left out when Apprise reads the URL the same without it:
    some hold for part of a service only, e.g. Email's STARTTLS for mailtos:// but not mailto://."""
    from apprise.utils.parse import parse_bool
    parts: list = []
    defaults: list = []
    for key, field in service["options"].items():
        value = str(values.get(key, "")).strip()
        default = service["args"].get(key)
        if field["type"] == "bool":
            if value == "":
                continue
            value = "yes" if parse_bool(value, bool(default)) else "no"
        if value == "":
            continue
        part = "%s=%s" % (urllib.parse.quote(key, safe=""), urllib.parse.quote(value, safe=""))
        (defaults if default is not None and same_value(value, default) else parts).append(part)
    path = str(values.get("path", "")).strip()
    if root_path(service) and path and not path.strip("/"):
        parts.append("path=/")
    rest = str(values.get(QUERY_FIELD, "")).lstrip("?")
    for part in defaults if base else []:
        without = "&".join(p for p in parts + [rest] if p)
        if not same_url(with_query(base, "&".join(p for p in parts + [part, rest] if p)),
                        with_query(base, without)):
            parts.append(part)
    return "&".join([part for part in parts + [rest] if part])


def normalize(url, plugin, services, schemas):
    """A pasted URL in Apprise's own form, so each setting sits under the name the fields use,
    e.g. ntfy's tags= as xtags=, Email's to= as its recipients, or a scheme the fields do not
    know; kept as given unless Apprise sets up the rewritten one exactly as the pasted one."""
    native = plugin.url(privacy=False)
    service_id = schemas.get(url_schema(native))
    if service_id is None:
        return url
    base, _, query = native.partition("?")
    args = services[service_id]["args"]
    # what the same URL renders with nothing set is the service's own defaults
    plain, _ = one_plugin(base)
    defaults = url_args(plain.url(privacy=False)) if plain is not None else {}
    options = services[service_id]["options"]
    # Apprise renders some files' addresses encoded twice, e.g. Discord's template: as pasted
    files, given = apprise_view(url)
    keep = []
    for part, key, value in query_pairs(query):
        if key in files and key in given:
            keep.append(f"{key}={urllib.parse.quote(given[key], safe='')}")
            continue
        if key in defaults and value == defaults[key]:
            continue
        if key in args and same_value(value, args[key]):
            continue
        keep.append(part)  # only what differs from the service's own defaults

    def rendered(candidate):
        again, _ = one_plugin(candidate)
        return again.url(privacy=False) if again is not None else None

    def unmatched(parts):
        return any(options.get(key, {}).get("type") == "choice" and value not in options[key]["values"]
                   for _, key, value in query_pairs("&".join(parts)))

    # Apprise renders some choices by name, e.g. Gotify's priority 8 as high: the field offers the
    # choice Apprise reads the same
    for i, (_, key, value) in enumerate(query_pairs("&".join(keep))):
        field = options.get(key) or {}
        if field.get("type") == "choice" and value not in field.get("values", []):
            for choice in field["values"]:
                tried = keep[:i] + [f"{key}={urllib.parse.quote(choice, safe='')}"] + keep[i + 1:]
                if rendered(with_query(base, "&".join(tried))) == native:
                    keep = tried
                    break
    # url() leaves some settings out, e.g. Email's from= or emojis=, so next the pasted URL's own
    # where a field takes them; and some of the URL ahead of its query, e.g. a user name a service
    # ignores, so next the pasted URL's own. The first Apprise sets up as it sets up the pasted one
    taken = {key for _, key, _ in query_pairs("&".join(keep))}
    pasted = [text for text, key, _ in query_pairs(url_query(url)) if key in options and key not in taken]
    candidates = [(head, parts) for head in (base, url.partition("?")[0]) for parts in (keep, keep + pasted)]
    for candidate in dict.fromkeys(with_query(head, "&".join(parts)) for head, parts in candidates if not unmatched(parts)):
        if rendered(candidate) == native and same_settings(url, plugin, candidate):
            return candidate
    # else, e.g. a choice Apprise names in a way no field choice matches: the URL as given, as before
    return url


def plugin_settings(plugin, names):
    """{name: value} of a plugin's attributes, class defaults included, objects read into a few
    levels deep; a repr's memory address left out."""
    def value(item, depth):
        if isinstance(item, enum.Enum):
            item = item.value
        if isinstance(item, (str, bytes, int, float, bool, type(None))):
            return item
        if depth and isinstance(item, (list, tuple)):
            return [value(i, depth - 1) for i in item]
        if depth and isinstance(item, (set, frozenset)):
            return sorted(repr(value(i, depth - 1)) for i in item)
        if depth and isinstance(item, dict):
            return {str(k): value(v, depth - 1) for k, v in item.items()}
        if depth and hasattr(item, "__dict__"):
            return [type(item).__name__, value(vars(item), depth - 1)]
        return re.sub(r" at 0x[0-9a-fA-F]+", "", repr(item))
    return {name: value(getattr(plugin, name, None), 8) for name in names}


def same_settings(first, plugin, second):
    """Whether Apprise builds from second a plugin set as the one built from first: url() leaves
    some settings out, e.g. emojis. What differs between two builds of first, e.g. a token's
    expiry, is not a setting; nor is fullpath, which each plugin that sends to it writes in url()."""
    twin, _ = one_plugin(first)
    other, _ = one_plugin(second)
    if twin is None or other is None:
        return False
    names = (set(vars(plugin)) | set(vars(other))) - {"fullpath"}
    mine, again, theirs = (plugin_settings(p, names) for p in (plugin, twin, other))
    return all(theirs[name] == mine[name] for name in names if again[name] == mine[name])


def apprise1_notes(url):
    """What Apprise 2 reads differently in a URL written for Apprise 1.13, which the migration
    rewrites in saved ones (M1_0_1), for an entered URL to say."""
    results = apprise_results(url) or {}
    qsd = results.get("qsd") or {}
    classes = plugin_classes(results.get("schema"))
    notes = []
    if "NotifyEmail" in classes and apprise1_pgp(str(qsd.get("pgp") or "")):
        notes.append("Apprise 2 reads pgp= as no, sign or encrypt; Apprise 1.13 read yes as encrypt.")
    # as Apprise 1.13: an empty pgpkey= is ignored and pgppub= wins
    if "NotifyEmail" in classes and qsd.get("pgpkey") and not qsd.get("pgppub"):
        notes.append("Apprise no longer reads pgpkey=; give the public key as pgppub=.")
    # version= or v=, or a .../notify/{token} URL, which is version 1
    if "NotifyAppriseAPI" in classes and not results.get("version"):
        notes.append("Apprise 2 sends the configuration ID in a header; choose version 1 for an Apprise API "
                     "server that reads it from the path.")
    # Apprise 1.13 read no path, in the URL or as path=, and sent to the host root
    if "NotifyFluxer" in classes and results.get("mode") == "private" and "path" not in qsd:
        notes.append("Apprise 2 sends to the path a Fluxer URL gives, else /api/; give path=/ for a server at "
                     "the host root, as Apprise 1.13 used.")
    if "NotifySimplePush" in classes:
        notes.append("Simplepush has moved to a new service, where a key for the previous one does not work; "
                     "give the API Token from the current Simplepush app.")
    return notes


def apprise1_pgp(value):
    """The PGP mode Apprise 1.13 read from a pgp= value that Apprise 2 refuses, or None: 1.13 took
    a mode's start as 2 does, else a yes or no (parse_bool, which 2 keeps as it was). The migration
    reads it the same (M1_0_1), which the tests hold it to."""
    from apprise.plugins.email.base import PGP_MODES
    from apprise.utils.parse import parse_bool
    if value.lower() in ("", "none") or any(mode.startswith(value.lower()) for mode in PGP_MODES):
        return None
    return "encrypt" if parse_bool(value) else "no"


def handed_over(path, prefix):
    """(the JSON request the web interface handed over under this name prefix, or None; why not)."""
    unread = None, "The request could not be read."
    name = os.path.basename(path)
    if not name.startswith(prefix):
        return unread
    try:
        with open(os.open(os.path.join(TEMP_DIR, name), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as handle:
            info = os.fstat(handle.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                return unread
            data = handle.read(REQUEST_MAX + 1)
        if len(data) > REQUEST_MAX:
            return None, f"The request is larger than {REQUEST_MAX // (1024 * 1024)} MB."
        request = json.loads(data)
    except (OSError, ValueError):
        return unread
    return (request, "") if isinstance(request, dict) else unread


def run_parse(path):
    """Fields for a URL the user pasted, so the dialog can fill itself in."""
    request, error = handed_over(path, "notify_parse_")
    if request is None:
        return {"error": error}
    url = str(request.get("url") or "").strip()
    if not url:
        return {"error": "Enter an Apprise URL to import."}
    notes = apprise1_notes(url)
    plugin, error = check_url(url, typed=True)
    if plugin is None:
        return {"error": " ".join(filter(None, [error] + notes))}
    services, schemas = apprise_services()
    url = normalize(url, plugin, services, schemas)
    described = describe_url(url, keep_secrets=True)
    if not described.get("service"):
        described["error"] = ("The fields cannot represent this URL exactly, so it is kept as it is. "
                              "Save it as a custom URL.")
    if notes:
        described["error"] = " ".join(filter(None, [described.get("error")] + notes))
    if text_email(plugin):
        described["textEmail"] = True
    return described


def secret_values(url, service, results):
    """What Apprise reads from a URL as secrets, decoded: the values of the service's private tokens
    and options, and the query's under a secret's name, a user name and a file's apart. Only those
    standing alone in the URL count: one that is also, say, the user name shows there anyway, and
    masking it would point it out."""
    found: list = []
    for field in [*service["tokens"].values(), *service["options"].values()]:
        value = results.get(field["map_to"]) if field["private"] and field["type"] != "file" else None
        found += value if isinstance(value, (list, tuple, set)) else [value]
    files = {k for k, f in service["options"].items() if f["type"] == "file"}
    found += [value for key, value in (results.get("qsd") or {}).items()
              if key in service["secrets"] and key != "user" and key not in files]
    found = [urllib.parse.unquote(str(value)) for value in found if value not in (None, "", KEY_MARKER)]
    text = urllib.parse.unquote(url)
    return {value for value in found if len(standing(value).findall(text)) <= 1}


def standing(*values):
    """A pattern for any of the values standing alone, not as a part of a longer word or token; the
    first that matches at a place wins, so give the longest first."""
    return re.compile(r"(?<![\w-])(?:%s)(?![\w-])" % "|".join(re.escape(value) for value in values))


def url_secrets(url):
    """secret_values of a URL; none when Apprise cannot read it."""
    try:
        services, schemas = apprise_services()
    except ImportError:
        return set()  # nor send it
    results = apprise_results(url)
    service_id = schemas.get(str(results["schema"]).lower()) if results is not None else None
    return secret_values(url, services[service_id], results) if service_id is not None else set()


def masked(text, secrets):
    """The text with each secret masked where it stands alone, as given or URL-quoted, e.g. a
    webhook's token in a connection error's address, or PagerTree's integration ID named in its
    own; read in one pass, the longest first, so one holding another goes whole."""
    forms = sorted(secrets | {urllib.parse.quote(s, safe="") for s in secrets}, key=len, reverse=True)
    return standing(*forms).sub("****", text) if forms else text


def read_into_field(service, url, results, key):
    """Whether Apprise reads a query name into one of the service's fields, listed as an alias or
    not: read again without it, the URL gives a field another value."""
    without = "&".join(text for text, name, _ in query_pairs(url_query(url)) if name != key)
    other = apprise_results(with_query(url.split("?", 1)[0], without))
    return other is None or any(other.get(t["map_to"]) != results.get(t["map_to"]) for t in service["tokens"].values())


def describe_url(url, keep_secrets=False):
    from apprise.utils.parse import parse_bool
    if not url:
        return {"service": ""}
    services, schemas = apprise_services()
    service_id, results, _ = parse_saved(url, services, schemas)
    if service_id is None:
        return {"service": "", "custom": True}
    service = services[service_id]
    tokens = service["tokens"]
    lists = {t["map_to"] for t in tokens.values() if t["type"] == "list"}
    shown = [k for k, t in tokens.items() if t["type"] == "list" or t["map_to"] not in lists]
    fields = saved_values(service, results, [k for k in shown if not tokens[k]["private"]])
    fields["schema"] = url_schema(url)
    secrets = saved_values(service, results, [k for k in shown if tokens[k]["private"]])
    hidden = secret_values(url, service, results)
    pairs = query_pairs(url_query(url))
    options = {key: value for _, key, value in pairs if key in service["options"]}
    rest = [pair for pair in pairs if pair[1] not in service["options"] and pair[1] not in service["filled"]]
    # the host root, which Apprise takes only as path=/, e.g. Fluxer's, shows as a Path of /
    roots = [value for _, key, value in rest if key == "path"]
    if root_path(service) and not fields.get("path", "").strip("/") and roots and roots[-1] and not roots[-1].strip("/"):
        fields["path"] = "/"
        rest = [pair for pair in rest if pair[1] != "path"]
    # a secret by name or a free-form argument, which no field masks, or a name Apprise reads into a
    # field, e.g. port= or Google Chat's threadkey=, where the query would win over the field
    if any(custom_arg(text, service["prefixes"]) or key in service["secrets"] or read_into_field(service, url, results, key)
           for text, key, _ in rest):
        return {"service": "", "custom": True}
    for key, value in options.items():
        field = service["options"][key]
        if field["type"] == "bool":
            value = "yes" if parse_bool(value, bool(service["args"].get(key))) else "no"  # as Apprise reads e.g. t
        (secrets if field["private"] else fields)[key] = value
    # a choice the URL leaves out shows what Apprise will use, where that is not its default
    plugin = check_url(url)[0]
    for key, field in service["options"].items():
        effective = getattr(plugin, field["map_to"], None) if plugin is not None and key not in options else None
        if field["type"] == "choice" and effective in field.get("values", ()) and effective != field.get("default"):
            fields[key] = effective
    # Apprise copies some secrets into another field, e.g. ntfy's token into its user: that field is
    # left to the private one, and the URL must rebuild without it
    fields = {k: v for k, v in fields.items() if not hidden & {v, *v.split(", ")}}
    if rest:
        fields[QUERY_FIELD] = "&".join(text for text, _, _ in rest)
    if keep_secrets:
        fields.update(secrets)  # pasted by the user a moment ago, so no point hiding them

    # a URL the fields cannot reproduce stays a plain URL, so saving never changes it
    values = {**fields, **secrets}
    rebuilt = compose(service, values)[0]
    query = query_from(service, values, rebuilt)
    if rebuilt is None or not same_url(with_query(rebuilt, query), url):
        return {"service": "", "custom": True}  # a URL the fields cannot hold, kept as it is
    return {"service": service_id, "fields": fields, "saved": sorted(secrets)}


def compose(service, values):
    """Fill the fullest template the values allow; returns (url, fields still wanted)."""
    lists = {t["map_to"]: k for k, t in service["tokens"].items() if t["type"] == "list"}
    best, wanted = None, None
    for template in service["templates"]:
        keys = re.findall(r"{(\w+)}", template)
        filled, missing = {}, []
        for key in keys:
            token = service["tokens"].get(key, {"type": "string", "map_to": key})
            value = values.get(key, "") or (token.get("default", "") if key == "schema" else "")
            if not value and token["type"] != "list" and token["map_to"] in lists:
                items = split_list(values.get(lists[token["map_to"]], ""))
                value = items[0] if len(items) == 1 else ""  # a single target fills e.g. {topic}
            if key in ("path", "fullpath"):
                # the template carries the separators, as in {host}/{path}, or not, as Fluxer's {host}{path}{webhook_id}
                before, _, after = template.partition("{" + key + "}")
                if before.endswith("/"):
                    value = value.lstrip("/")
                elif value.strip("/"):
                    value = "/" + value.strip("/") + ("/" if after.startswith("{") else "")
                else:
                    value = ""
            if not value:
                missing.append(key)
                continue
            if token["type"] == "list":
                filled[key] = "/".join(urllib.parse.quote(item, safe="") for item in split_list(value))
            elif key == "host":
                filled[key] = urllib.parse.quote(value, safe="[]:")
            elif key in ("path", "fullpath"):
                filled[key] = urllib.parse.quote(value, safe="/")
            else:
                filled[key] = urllib.parse.quote(value, safe="")
        if missing:
            # the closest template is the one asking for the least
            if wanted is None or len(missing) < len(wanted):
                wanted = missing
        elif best is None or len(keys) > best[0]:
            best = (len(keys), template.format_map(filled))
    if best is not None:
        return best[1], []
    labels = [str(service["tokens"].get(key, {}).get("label", key)) for key in wanted or []]
    return None, labels


def split_list(value):
    return [item for item in re.split(r"[\s,]+", value) if item]


def several_urls(url):
    """Whether Apprise's add() would split a URL string into several services; without a scheme it
    splits at spaces, which is no URL at all rather than several."""
    from apprise.utils.parse import parse_urls
    return "://" in (url or "") and len(parse_urls(url)) > 1


def one_plugin(url, typed=False, asset=None):
    """(the one plugin Apprise builds from a URL, error text): what is checked and what is sent
    through; a plugin tripping over the URL still means a bad URL. typed: all of the URL was just
    entered, none of it saved."""
    import apprise
    with apprise_log() as captured:
        try:
            plugin = apprise.Apprise.instantiate(url, asset=asset)
        except Exception:
            plugin = None
    if plugin is None:
        # the reason comes before "Could not load"; a saved URL's quoted value may be a secret
        lines = logged(captured)
        if len(lines) > 1 and lines[-1].startswith("Could not load "):
            reason = lines[-2]
        else:
            reason = lines[-1] if lines else ""
        if not typed:
            # first quote or parenthesis to the last, so a value holding one goes whole, and a URL
            # but for its scheme, e.g. in "Unparseable Telegram URL ..."
            reason = re.sub(r"\s*\(.*\)|\s+'.*'", "", reason, flags=re.S).strip()
            reason = re.sub(r"\b([A-Za-z][\w+.-]*)://\S*", r"\1://...", reason)
        return None, reason or "This is not a valid Apprise URL."
    return plugin, ""


def refused(url):
    """Why a URL is not given to Apprise at all, or "": a string its add() would split into several
    services, the later ones unchecked, one naming a file, or one Apprise would send elsewhere."""
    if several_urls(url):
        return "Give one URL per channel; add a channel for each further service."
    local = local_file_args(url)
    if local:
        plain = plain_http_args(url, local)
        if plain:
            return f"Give an https:// address for {', '.join(plain)}, or paste its contents in the channel."
        return (f"The URL names a file in {', '.join(local)}; choose its service in the channel and paste its "
                "contents instead.")
    # Apprise does not read every IPv6 address, e.g. not one in uppercase or with some zone IDs:
    # ntfy, Fluxer and LaMetric then take it for no server and send to their cloud, unless told the
    # mode, and email drops it
    results = apprise_results(url) or {}
    host = str(results.get("host") or "")
    given = re.match(r"[^:]*:[/\\]*(?:[^/\\?]*@)?\[", url or "")
    if (results.get("mode") == "cloud" and "mode" not in (results.get("qsd") or {}) and re.search(r"[\[\]:%]", host)) \
            or (given and results and not host):
        return "Apprise cannot read this server address; give the server's name, or an address in lowercase without a zone ID."
    return ""


def check_url(url, typed=False):
    """(apprise plugin, error text) for a URL; one naming a file is refused before Apprise builds
    a plugin from it."""
    error = refused(url)
    return (None, error) if error else one_plugin(url, typed)


def from_service(service_id, fields, stored):
    """Compose a URL from the dialog's service fields; returns (url, pasted files, error text)."""
    services, schemas = apprise_services()
    service = services.get(service_id)
    if service is None:
        return "", {}, "Apprise does not know this service."
    saved_id, results, _ = parse_saved(stored, services, schemas) if stored else (None, {}, "")
    known = set(service["tokens"]) | set(service["options"]) | {QUERY_FIELD}
    # optional secrets the dialog was told to remove, unless a new value was typed to replace them
    cleared = {k for k, f in service["options"].items()
               if f["private"] and fields.get(f"__clear_{k}") == "1" and fields.get(k, "") == ""}
    values = {k: v for k, v in fields.items() if k in known and v != "" and k not in cleared}
    if saved_id == service_id:
        private = [k for k, t in service["tokens"].items() if t["private"] and k not in values]
        values.update(saved_values(service, results, private))
        # secret options are masked too, so keep what was stored
        stored_options, _ = split_query(service, url_query(stored))
        for key, value in stored_options.items():
            if service["options"][key]["private"] and key not in values and key not in cleared:
                values[key] = value
    files = {}
    for key in [k for k, f in service["options"].items() if f["type"] == "file" and k in values]:
        value = values[key]
        if value == KEY_MARKER:
            continue  # already stored
        if re.match(r"https?://\S+$", value, re.I):
            if key.lower() not in REMOTE_FILE_ARGS:
                return "", {}, f"Paste the {service['options'][key]['label']} itself; a private key is not fetched."
            if not re.match(r"https://", value, re.I):
                # could be swapped in transit
                return "", {}, f"Give an https:// address for the {service['options'][key]['label']}."
            continue  # fetched from that address
        if len(value) > KEY_MAX:
            return "", {}, f"The {service['options'][key]['label']} is larger than a key or template should be."
        files[key.lower()] = value.replace("\r\n", "\n") + ("" if value.endswith("\n") else "\n")
        values[key] = KEY_MARKER
    url, wanted = compose(service, values)
    if url is None:
        needed = ", ".join(wanted) if wanted else "the fields this service needs"
        return "", {}, f"Fill in {needed}; see the setup guide if you are unsure."
    query = query_from(service, values, url)
    return with_query(url, query), files, ""


def shown_url(plugin, url):
    """The saved URL as shown, not used: as typed, e.g. an address's @ rather than %40, with its
    secrets masked, also where Apprise leaves one; for a webhook
    receiver (PATH_SECRET) the path is left out too, since there the secret is often the path."""
    shown = masked(urllib.parse.unquote(plugin.url(privacy=True).split("?", 1)[0]), url_secrets(url))
    parts = urllib.parse.urlsplit(shown)
    if class_names(type(plugin)) & set(PATH_SECRET) and parts.path.strip("/"):
        shown = urllib.parse.urlunsplit((parts.scheme, parts.netloc, "/...", "", ""))
    return shown


def run_build(path):
    request, error = handed_over(path, "notify_build_")
    if request is None or not isinstance(request.get("fields") or {}, dict):
        return {"error": error or "The request could not be read.", "field": "channel.url"}
    uuid = str(request.get("uuid") or "")
    channel = saved_channel(uuid)
    stored = channel.get("url", "")
    service_id = str(request.get("service") or "")
    # a choice box with nothing selected posts null, which is not a value
    fields = {str(k): str(v).strip() for k, v in (request.get("fields") or {}).items() if v is not None}

    files: dict = {}
    if service_id and (fields.get("changed") == "1" or not stored):
        url, files, error = from_service(service_id, fields, stored)
        typed = not stored  # fields left empty keep the saved values
        target_field = "apprise_service"
    else:
        typed = bool(str(request.get("url") or "").strip())
        url = str(request.get("url") or "").strip() or stored
        error = "" if url else "Enter an Apprise URL or choose a service."
        target_field = "channel.url"
    if error:
        return {"error": error, "field": target_field}

    plugin, error = check_url(url, typed)
    if plugin is None:
        # a URL written by hand may be one for Apprise 1.13, as an import says
        notes = apprise1_notes(url) if typed and target_field == "channel.url" else []
        return {"error": " ".join([error] + notes), "field": target_field}
    masked = shown_url(plugin, url)
    # keep the stored files the URL still points at, with anything newly pasted on top
    stored_args = stored_file_args(url)
    kept = {key: value for key, value in (channel.get("files") or {}).items() if key in stored_args}
    kept.update(files)
    missing = [key for key in stored_args if key not in kept]
    if missing:
        return {"error": f"Paste the file for {', '.join(missing)}.", "field": target_field}
    return {"url": url, "service": str(plugin.service_name), "target": masked, "files": kept}


if __name__ == "__main__":
    syslog.openlog("notify", logoption=syslog.LOG_PID, facility=syslog.LOG_USER)
    if len(sys.argv) > 1 and sys.argv[1] == "check":
        run_check()
    elif len(sys.argv) > 1 and sys.argv[1] == "boot":
        run_boot()
    elif len(sys.argv) > 1 and sys.argv[1] == "status":
        print(json.dumps(run_status()))
    elif len(sys.argv) > 2 and sys.argv[1] in ("test", "summary"):
        verb = "The test could not be run" if sys.argv[1] == "test" else "The summary could not be sent"
        try:
            result = with_lock(30, lambda: (run_test if sys.argv[1] == "test" else run_summary)(sys.argv[2]))
        except Exception as exc:  # an answer, so the dialog can say what went wrong
            result = {"status": "failed", "message": f"{verb}: {exc}"}
        busy = {"status": "failed", "message": f"{verb}; a check is still running, so try again in a minute."}
        print(json.dumps(result or busy))
    elif len(sys.argv) > 1 and sys.argv[1] == "reports":
        print(json.dumps(run_reports()))
    elif len(sys.argv) > 2 and sys.argv[1] == "report":
        print(json.dumps(run_report(sys.argv[2])))
    elif len(sys.argv) > 2 and sys.argv[1] == "delete":
        print(json.dumps(run_delete(sys.argv[2])))
    elif len(sys.argv) > 1 and sys.argv[1] == "services":
        print(json.dumps(run_services()))
    elif len(sys.argv) > 2 and sys.argv[1] == "describe":
        print(json.dumps(run_describe(sys.argv[2])))
    elif len(sys.argv) > 2 and sys.argv[1] == "parse":
        print(json.dumps(run_parse(sys.argv[2])))
    elif len(sys.argv) > 2 and sys.argv[1] == "build":
        print(json.dumps(run_build(sys.argv[2])))
    else:
        print(f"usage: {sys.argv[0]} check | boot | status | test <uuid> | summary <uuid> | reports | report <name> | delete <name> | services | "
              f"describe <uuid> | parse <file> | build <file>",
              file=sys.stderr)
        sys.exit(1)
