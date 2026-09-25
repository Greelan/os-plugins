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
import functools
import http.client
import json
import os
import re
import socket
import subprocess
import sys
import syslog
import time
import urllib.parse
import xml.etree.ElementTree as ET

# Apprise, Markdown and PyYAML are vendored under lib/ (pure-Python), so the plugin
# works with whichever Python the OPNsense series ships
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "lib"))

CONFIG = "/conf/config.xml"
STATE = "/var/db/notify/state.json"
SETTINGS_CACHE = "/var/db/notify/settings.json"
SETTINGS_SCRIPT = "/usr/local/opnsense/scripts/OPNsense/Notify/settings.php"
SETTINGS_FORMAT = 2
FIRMWARE = "/tmp/pkg_upgrade.json"
MONIT_SOCKET = "/var/run/monit.sock"
AUDIT_LOG = "/var/log/audit"
IDS_LOG = "/var/log/suricata/eve.json"
CONFIGCTL = "/usr/local/sbin/configctl"
PFCTL = "/sbin/pfctl"
APCACCESS = "/usr/local/sbin/apcaccess"
UPSC = "/usr/local/bin/upsc"
# NUT's flags, spelled out (apcupsd already reports words)
UPS_FLAGS = {"OL": "online", "OB": "on battery", "LB": "low battery", "RB": "replace battery",
             "CHRG": "charging", "DISCHRG": "discharging", "BYPASS": "on bypass", "CAL": "calibrating",
             "OFF": "off", "OVER": "overloaded", "TRIM": "trimming voltage", "BOOST": "boosting voltage"}

# backoff between delivery attempts, then hourly until RETRY_SECONDS is up
RETRY_DELAYS = (60, 120, 300, 600, 1800, 3600)
RETRY_SECONDS = 86400
QUEUE_MAX = 100
CERT_INTERVAL = 3600
# System Status entries change slowly and cost a PHP call to collect
STATUS_INTERVAL = 300
# the host list is a database read; new devices are not urgent
DEVICE_INTERVAL = 300
# field holding the query part of a built URL, e.g. priority=high&format=markdown
QUERY_FIELD = "__query"
# URL arguments Apprise opens as a file on every send, by plugin class (subclasses included);
# elsewhere, e.g. MSG91 or SendGrid, a template is only an ID. The dialog takes the file's
# contents, which are stored with the channel and written under KEY_DIR at send time; the URL
# then carries KEY_MARKER. Any other local path is refused, so a channel cannot make root read a
# file of its choosing.
FILE_ARGS = {
    "NotifyDiscord": ("template",), "NotifyTelegram": ("template",), "NotifySlack": ("template",),
    "NotifyWorkflows": ("template",), "NotifyFCM": ("keyfile",), "NotifyVapid": ("keyfile", "subfile"),
    "NotifyEmail": ("pgppub", "pgpkey", "pgpprv"),
}
# files that may instead be fetched from an https address; private keys are never fetched
REMOTE_FILE_ARGS = ("template", "pgppub", "pgpkey")
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
KEY_MAX = 64 * 1024
# recorded state older than this predates a pause (disabled, or the firewall was off),
# so it is dropped rather than compared against
STALE_SECONDS = 3600
# a WireGuard peer counts as gone once its last handshake is this old
HANDSHAKE_SECONDS = 300
# lines or alerts read from a log in one pass, so a busy log cannot stall a check
LOG_LINES = 500
LOG_BYTES = 2 * 1024 * 1024
# devices remembered, oldest dropped first
DEVICES_MAX = 4096

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

# System Status codes (OPNsense\System\SystemStatusCode)
STATUS_LEVELS = {"error": -1, "warning": 0, "notice": 1}
STATUS_TYPES = {-1: "failure", 0: "warning", 1: "info"}


def log(priority, message):
    syslog.syslog(priority, message)


def text(node, path, default=""):
    value = node.findtext(path) if node is not None else None
    return value if value is not None else default


def load_config():
    """Settings from the models, via settings.php; cached until config.xml changes."""
    try:
        stat = os.stat(CONFIG)
        source = [stat.st_mtime_ns, stat.st_size, SETTINGS_FORMAT]
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

    try:
        result = subprocess.run([SETTINGS_SCRIPT], capture_output=True, text=True, timeout=60)
        config = json.loads(result.stdout)
    except (OSError, subprocess.SubprocessError, ValueError) as error:
        log(syslog.LOG_ERR, f"settings could not be read: {error}")
        return None

    if source is not None:
        save_cache({"source": source, "config": config})
    return config


def save_cache(payload):
    """The cache holds the channel URLs, so it is written private and replaced whole."""
    tmp = SETTINGS_CACHE + ".tmp"
    try:
        os.makedirs(os.path.dirname(SETTINGS_CACHE) or ".", mode=0o700, exist_ok=True)
        handle = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(handle, "w") as stream:
            os.fchmod(stream.fileno(), 0o600)  # the mode above applies to a new file only
            json.dump(payload, stream)
        os.replace(tmp, SETTINGS_CACHE)
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
    """The recorded state, keeping only the queue once it is too old to compare against."""
    state = load_state()
    if int(time.time()) - state.get("stamp", 0) > STALE_SECONDS:
        state = {"queue": state.get("queue", [])}  # queued items expire on their own
    return state


def save_state(state):
    """The queue holds message bodies, so the state is written private like the cache."""
    os.makedirs(os.path.dirname(STATE) or ".", mode=0o700, exist_ok=True)
    tmp = STATE + ".tmp"
    handle = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(handle, "w") as stream:
        os.fchmod(stream.fileno(), 0o600)  # the mode above applies to a new file only
        json.dump(state, stream)
    os.replace(tmp, STATE)


def configctl_json(*args):
    """JSON from a configd action, or None; a missing action is a plugin bug, so say so.

    PHP renders an empty array as [], so an empty answer comes back as {}.
    """
    result = None
    try:
        result = subprocess.run([CONFIGCTL] + list(args), capture_output=True, text=True, timeout=120)
        answer = json.loads(result.stdout)
        return {} if answer == [] else answer
    except (OSError, subprocess.SubprocessError, ValueError):
        answer = result.stdout[:100].strip() if result is not None else ""
        log(syslog.LOG_DEBUG, f"no usable answer from \"{' '.join(args)}\": {answer}")
        return None


def duration(seconds):
    seconds = int(max(seconds, 0))
    days, seconds = divmod(seconds, 86400)
    hours, seconds = divmod(seconds, 3600)
    minutes, seconds = divmod(seconds, 60)
    parts = [(days, "d"), (hours, "h"), (minutes, "m"), (seconds, "s")]
    shown = [f"{value}{unit}" for value, unit in parts if value]
    return " ".join(shown[:2]) if shown else "0s"


def clock(timestamp):
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(timestamp))


def message(event, ntype, title, body):
    # a notification with an empty body is refused on delivery, so fall back to the title
    return {"event": event, "type": ntype, "title": title, "body": body or title,
            "time": int(time.time())}


def follow(path, previous):
    """New lines of a log since the last pass, with the position to remember."""
    try:
        stat = os.stat(path)
    except OSError:
        return [], previous
    position = previous.get("offset", 0) if previous.get("inode") == stat.st_ino else 0
    if position > stat.st_size:
        position = 0  # truncated
    position = max(position, stat.st_size - LOG_BYTES)  # skip a flood rather than read it all
    state = {"inode": stat.st_ino, "offset": stat.st_size, "path": path}
    if previous.get("inode") is None:
        return [], state  # first sight of this file, start from the end
    try:
        with open(path, "rb") as handle:
            handle.seek(position)
            raw = handle.readlines()
            state["offset"] = handle.tell()
    except OSError:
        return [], previous
    lines = [line.decode("utf-8", "replace") for line in raw]
    return lines[-LOG_LINES:], state


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
    try:
        hold = int(config["general"].get("gatewayHold", "0"))
    except ValueError:
        hold = 0
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
    try:
        with open(FIRMWARE) as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        return previous, []  # absent while a check runs
    if data.get("connection") != "ok":
        return previous, []
    upgrades = data.get("upgrade_packages") or []
    new = data.get("new_packages") or []
    major = data.get("upgrade_major_version") or ""
    key = json.dumps([sorted(f"{p.get('name')}-{p.get('new_version', p.get('version'))}" for p in upgrades + new),
                      major]) if upgrades or new or major else ""
    if not key or key == previous:
        return key, []
    packages = [f"{p.get('name')} {p.get('current_version')} -> {p.get('new_version')}" for p in upgrades]
    packages += [f"{p.get('name')} {p.get('version')} (new)" for p in new]
    lines = packages if len(packages) <= FIRMWARE_PACKAGES else \
        [f"{len(upgrades)} package upgrade(s), {len(new)} new package(s)."]
    if major:
        lines.append(f"Major upgrade to {major} is available.")
    if data.get("upgrade_needs_reboot") == "1" or data.get("needs_reboot") == "1":
        lines.append("The update requires a reboot.")
    return key, [message("firmware", "info", "Firmware updates are available", "\n".join(lines))]


def check_auth(config, previous):
    logins = config["general"].get("authLogins", "0") == "1"
    lines, state = follow(audit_log(), previous or {})
    messages = []
    for line in lines:
        body = line.strip()
        lowered = body.lower()
        if any(hint in lowered for hint in AUTH_LOCKOUT):
            messages.append(message("auth", "failure", "Login blocked", body))
        elif any(hint in lowered for hint in AUTH_FAILURE):
            messages.append(message("auth", "warning", "Failed login", body))
        elif logins and any(hint in lowered for hint in AUTH_SUCCESS):
            messages.append(message("auth", "info", "Login", body))
    return state, messages


def check_certificate(config, previous):
    previous = previous or {}
    now = int(time.time())
    if now - previous.get("checked", 0) < CERT_INTERVAL:
        return previous, []
    try:
        days = int(config["general"].get("certDays", "14"))
    except ValueError:
        days = 14
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
    data = configctl_json("system", "status")
    if not isinstance(data, dict):
        return previous, []
    seen = previous.get("items")
    threshold = STATUS_LEVELS.get(config["general"].get("statusLevel", "warning"), 0)
    current, messages = {}, []
    for name, item in data.items():
        try:
            code = int(item.get("statusCode"))
        except (TypeError, ValueError):
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
        if name in current:
            continue
        gone = was[3] if len(was) > 3 else name
        messages.append(message("status", "success", f"{gone} is resolved",
                                f"Was: {was[1]}" if was[1] else ""))
    return {"checked": now, "items": current}, messages


class UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, path):
        super().__init__("localhost", timeout=30)
        self.path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.path)


def check_monit(config, previous):
    if not os.path.exists(MONIT_SOCKET):
        return previous, []
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
        if response.status != 200:
            return previous, []
        root = ET.fromstring(response.read())
    except (OSError, http.client.HTTPException, ET.ParseError):
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


@functools.lru_cache(maxsize=1)
def ifconfig():
    try:
        return subprocess.run(["/sbin/ifconfig", "-a"], capture_output=True, text=True, timeout=30).stdout
    except (OSError, subprocess.SubprocessError):
        return ""


def carp_states():
    """CARP states of every virtual IP on this firewall."""
    return re.findall(r"^\s+carp: (\S+) vhid", ifconfig(), re.M)


def is_carp_backup(config):
    """True when this firewall has CARP virtual IPs and none of them is master."""
    if config["general"].get("carpMasterOnly", "0") != "1":
        return False
    states = carp_states()
    return bool(states) and "MASTER" not in states


def check_vpn(config, previous):
    now = int(time.time())
    current, messages = {}, []
    peers = configctl_json("wireguard", "show") or {}
    for record in peers.get("records", []) if isinstance(peers, dict) else []:
        if record.get("type") != "peer":
            continue
        name = f"WireGuard {record.get('if', '?')} {str(record.get('public-key', ''))[:12]}"
        handshake = record.get("latest-handshake") or 0
        current[name] = "up" if handshake and now - handshake < HANDSHAKE_SECONDS else "down"
    sessions = configctl_json("openvpn", "connections", "server,client") or {}
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
        if previous is None or last == level:
            continue
        if level == "up":
            messages.append(message("vpn", "success", f"{name} is connected", ""))
        else:
            messages.append(message("vpn", "warning", f"{name} is disconnected", ""))
    for name in (previous or {}):
        if name not in current and previous[name] == "up":
            messages.append(message("vpn", "warning", f"{name} is disconnected", ""))
    return current, messages


def check_device(config, previous):
    now = int(time.time())
    if previous is not None and now - previous.get("checked", 0) < DEVICE_INTERVAL:
        return previous, []
    hosts = configctl_json("hostwatch", "dump_full")
    if not isinstance(hosts, dict):
        return previous, []
    known = list((previous or {}).get("macs", []))
    seen = set(known)
    messages = []
    for row in hosts.get("rows", []):
        if len(row) < 3 or not row[1]:
            continue
        interface, mac, address = row[0], row[1].lower(), row[2]
        if mac in seen:
            continue
        seen.add(mac)
        known.append(mac)
        if previous is None:
            continue  # first pass records what is already there
        vendor = row[3] if len(row) > 3 and row[3] else "unknown vendor"
        messages.append(message("device", "info", f"New device on {interface}",
                                f"{mac} ({vendor}) at {address}"))
    return {"checked": now, "macs": known[-DEVICES_MAX:]}, messages


def check_ids(config, previous):
    try:
        severity = int(config["general"].get("idsSeverity", "1"))
    except ValueError:
        severity = 1
    lines, state = follow(IDS_LOG, previous or {})
    messages = []
    for line in lines:
        try:
            event = json.loads(line)
        except ValueError:
            continue
        alert = event.get("alert") if event.get("event_type") == "alert" else None
        if not alert or int(alert.get("severity", 3)) > severity:
            continue
        where = f"{event.get('src_ip', '?')} -> {event.get('dest_ip', '?')}"
        messages.append(message("ids", "warning", alert.get("signature", "IDS alert"),
                                f"{where}\nSeverity {alert.get('severity')}, {alert.get('category', '')}"))
    return state, messages


def check_carp(config, previous):
    names = config.get("interfaces", {})
    current, messages, device = {}, [], None
    for line in ifconfig().splitlines():
        match = re.match(r"^(\S+): flags=", line)
        if match:
            device = match.group(1)
            continue
        match = re.match(r"^\s+carp: (\S+) vhid (\d+)", line)
        if not match or device is None:
            continue
        key = f"{match.group(2)}@{device}"
        current[key] = match.group(1)
        last = (previous or {}).get(key)
        if previous is None or last is None or last == current[key]:
            continue
        ntype = "info" if current[key] == "MASTER" else "warning"
        title = f"CARP vhid {match.group(2)} on {names.get(device, device)} is now {current[key]}"
        messages.append(message("carp", ntype, title, f"Changed from {last}."))
    return current, messages


def addresses():
    """Device -> the addresses it holds, link-local and loopback aside."""
    found: dict = {}
    device = None
    for line in ifconfig().splitlines():
        match = re.match(r"^(\S+): flags=", line)
        if match:
            device = match.group(1)
            continue
        match = re.match(r"^\s+inet6? (\S+)", line)
        if match is None or device is None:
            continue
        address = match.group(1).split("%")[0]
        if address.startswith(("fe80:", "127.", "::1")):
            continue
        if " temporary" in line or " deprecated" in line:
            continue  # privacy addresses rotate; reporting each one would be noise
        found.setdefault(device, []).append(address)
    return found


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
    device = None
    for line in ifconfig().splitlines():
        match = re.match(r"^(\S+): flags=", line)
        if match:
            device = match.group(1)
            continue
        match = re.match(r"^\s+status: (.+)$", line)
        if match is None or device is None or device not in names:
            continue
        current[device] = match.group(1).strip()
        last = (previous or {}).get(device)
        if previous is None or last is None or last == current[device]:
            continue
        up = current[device] in ("active", "associated")
        messages.append(message("link", "success" if up else "failure",
                                f"{names[device]} link is {current[device]}", f"Was {last}."))
    return current, messages


def check_states(config, previous):
    """The firewall state table against its limit."""
    try:
        threshold = int(config["general"].get("statesPercent", "80"))
    except ValueError:
        threshold = 80
    try:
        info = subprocess.run([PFCTL, "-si"], capture_output=True, text=True, timeout=30).stdout
        limits = subprocess.run([PFCTL, "-sm"], capture_output=True, text=True, timeout=30).stdout
    except (OSError, subprocess.SubprocessError):
        return previous, []
    found = re.search(r"current entries\s+(\d+)", info)
    allowed = re.search(r"states\s+hard limit\s+(\d+)", limits)
    if found is None or allowed is None:
        return previous, []  # no limit to measure against, e.g. "states unlimited"
    entries, limit = int(found.group(1)), int(allowed.group(1))
    percent = entries * 100 // max(limit, 1)
    current = {"over": percent >= threshold}
    if previous is None or previous.get("over") == current["over"]:
        return current, []
    detail = f"{entries} of {limit} states ({percent}%)."
    if current["over"]:
        return current, [message("states", "warning", "Firewall state table is filling up", detail)]
    return current, [message("states", "success", "Firewall state table is back to normal", detail)]


def ups_status():
    """(name, state, detail) per UPS, from apcupsd or NUT, whichever is installed."""
    found = []
    if os.access(APCACCESS, os.X_OK):
        try:
            output = subprocess.run([APCACCESS, "status"], capture_output=True, text=True,
                                    timeout=30).stdout
        except (OSError, subprocess.SubprocessError):
            output = ""
        values = dict(line.split(":", 1) for line in output.splitlines() if ":" in line)
        values = {k.strip().upper(): v.strip() for k, v in values.items()}
        if values.get("STATUS"):
            detail = ", ".join(filter(None, [
                f"battery {values['BCHARGE']}" if values.get("BCHARGE") else "",
                f"{values['TIMELEFT']} left" if values.get("TIMELEFT") else "",
                f"input {values['LINEV']}" if values.get("LINEV") else "",
            ]))
            found.append((values.get("UPSNAME") or "UPS", values["STATUS"].lower(), detail))
    if os.access(UPSC, os.X_OK):
        try:
            listed = subprocess.run([UPSC, "-l"], capture_output=True, text=True, timeout=30).stdout
            for name in [n.strip() for n in listed.splitlines() if n.strip()]:
                output = subprocess.run([UPSC, name], capture_output=True, text=True,
                                        timeout=30).stdout
                values = dict(line.split(":", 1) for line in output.splitlines() if ":" in line)
                values = {k.strip(): v.strip() for k, v in values.items()}
                flags = [UPS_FLAGS.get(f, f) for f in values.get("ups.status", "").split()]
                if not flags:
                    continue
                detail = ", ".join(filter(None, [
                    f"battery {values['battery.charge']}%" if values.get("battery.charge") else "",
                    f"{int(values['battery.runtime']) // 60} min left"
                    if values.get("battery.runtime", "").isdigit() else "",
                ]))
                found.append((name, " ".join(flags), detail))
        except (OSError, subprocess.SubprocessError, ValueError):
            pass
    return found


def check_ups(config, previous):
    """Power state from apcupsd or NUT, when either is installed."""
    current, messages = {}, []
    for name, state, detail in ups_status():
        current[name] = state
        last = (previous or {}).get(name)
        if previous is None or last is None or last == state:
            continue
        good = any(hint in state for hint in ("online", "on line"))
        low = "low battery" in state or "replace" in state
        messages.append(message("ups", "success" if good else ("failure" if low else "warning"),
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
    ("status", check_status),
    ("carp", check_carp),
    ("wanip", check_wanip),
    ("link", check_link),
    ("states", check_states),
    ("ups", check_ups),
)


# ------------------------------------------------------------------ delivery


def file_args(schema):
    """The URL arguments the service behind a schema opens as files."""
    from apprise.plugins import N_MGR
    plugin = N_MGR[schema] if schema in N_MGR else None
    names = {c.__name__ for c in plugin.__mro__} if plugin is not None else set()
    return {arg for name, args in FILE_ARGS.items() if name in names for arg in args}


def local_file_args(url):
    """The arguments of a URL that would make Apprise read a file this plugin did not write, or
    fetch a private key from elsewhere."""
    args = file_args(url_schema(url))
    return [key for key, value in urllib.parse.parse_qsl(urllib.parse.urlsplit(url).query)
            if key.lower() in args and value != KEY_MARKER
            and not (key.lower() in REMOTE_FILE_ARGS and re.match(r"https?://", value, re.I))]


def file_label(schema, arg):
    """(label, hint) for a file argument, or None."""
    from apprise.plugins import N_MGR
    plugin = N_MGR[schema] if schema in N_MGR else None
    names = {c.__name__ for c in plugin.__mro__} if plugin is not None else set()
    for (name, key), label in FILE_LABELS.items():
        if key == arg and (name is None or name in names):
            return label
    return None


def stored_file_args(url):
    """The arguments of a URL whose file the channel stores."""
    args = file_args(url_schema(url))
    return [key.lower() for key, value in urllib.parse.parse_qsl(urllib.parse.urlsplit(url).query)
            if key.lower() in args and value == KEY_MARKER]


def with_key_files(channel):
    """The channel URL with each stored file written out and its marker replaced by the path."""
    url, files = channel.get("url", ""), channel.get("files") or {}
    args = file_args(url_schema(url))
    base, sep, query = url.partition("?")
    parts = []
    for part in query.split("&") if sep else []:
        key, eq, value = part.partition("=")
        if eq and key.lower() in args and value == KEY_MARKER:
            content = files.get(key.lower())
            if not isinstance(content, str) or content == "":
                raise ValueError(f"The file for {key} is not stored with this channel; paste it again.")
            path = os.path.join(KEY_DIR, f"{channel['uuid']}-{key.lower()}")
            write_private(path, content)
            part = f"{key}={urllib.parse.quote(path, safe='')}"
        parts.append(part)
    return base + (sep + "&".join(parts) if sep else "")


def write_private(path, content):
    """A file only root can read, rewritten only when its contents change."""
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    try:
        with open(path) as current:
            if current.read() == content:
                return
    except OSError:
        pass
    tmp = path + ".tmp"
    handle = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(handle, "w") as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write(content)
    os.replace(tmp, path)


def prune_key_files(channels):
    """Remove the key files of channels, or arguments, that no longer use them."""
    wanted = {f"{c['uuid']}-{key}" for c in channels for key in stored_file_args(c.get("url", ""))}
    try:
        names = os.listdir(KEY_DIR)
    except OSError:
        return
    for name in names:
        if name not in wanted:
            try:
                os.unlink(os.path.join(KEY_DIR, name))
            except OSError:
                pass


def deliver(channel, title, body, ntype):
    """Send one notification; returns (ok, error text)."""
    try:
        import apprise
    except ImportError as exc:
        return False, f"The bundled Apprise could not be loaded: {exc}"
    local = local_file_args(channel.get("url", ""))
    if local:
        # also covers channels saved before such URLs were refused
        return False, f"The URL names a file in {', '.join(local)}; paste its contents in the channel instead."
    try:
        url = with_key_files(channel)
    except (ValueError, OSError) as exc:
        return False, str(exc)
    with apprise.LogCapture(level=apprise.logging.WARNING, fmt="%(message)s") as captured:
        notifier = apprise.Apprise()
        if not notifier.add(url):
            return False, "The URL is not a valid Apprise URL."
        # the text carries outsiders' input, e.g. a failed login's user name, so services that
        # render HTML get it escaped rather than as markup
        ok = bool(notifier.notify(body=body, title=title, notify_type=ntype,
                                  body_format=apprise.NotifyFormat.TEXT))
        errors = [line for line in captured.getvalue().splitlines() if line.strip()]
    return ok, "" if ok else (errors[-1] if errors else "Delivery failed.")


def title_prefix(general, hostname):
    """What goes in front of every title: the host name, custom text or nothing."""
    setting = general.get("titlePrefix", "hostname")
    if setting == "none":
        return ""
    if setting == "custom":
        return general.get("titleText", "").strip()
    return hostname


def wants(channel, item):
    if item["event"] == "digest":
        return True  # already filtered when it was built
    if item["event"] not in channel["events"]:
        return False
    names = channel.get("monit") or []
    return not (item["event"] == "monit" and names and item.get("service") not in names)


def digest(items, threshold):
    """Fold a burst for one channel into a single notification."""
    if threshold < 1 or len(items) < threshold:
        return items
    lines = [f"- {item['title']}" for item in items]
    types = [item["type"] for item in items]
    kind = "failure" if "failure" in types else ("warning" if "warning" in types else "info")
    summary = message("digest", kind, f"{len(items)} notifications", "\n".join(lines))
    return [dict(summary, uuid=items[0]["uuid"])]


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
        if channel is None or not wants(channel, item):
            continue
        if now - item["time"] > RETRY_SECONDS:
            log(syslog.LOG_ERR, f"gave up on \"{item['title']}\" for {name} after "
                                f"{duration(now - item['time'])}")
            continue
        if now < item.get("retry", 0):
            pending.append(item)  # waiting out the backoff
            continue
        title = f"{prefix}: {item['title']}" if prefix else item["title"]
        body = item["body"]
        if now - item["time"] > 90:
            body += f"\n\n(Delayed: this happened at {clock(item['time'])}.)"
        ok, error = deliver(channel, title, body, item["type"])
        if ok:
            log(syslog.LOG_NOTICE, f"sent \"{item['title']}\" to {name}")
            continue
        tries = item.get("tries", 0) + 1
        delay = RETRY_DELAYS[min(tries, len(RETRY_DELAYS)) - 1]
        item.update(tries=tries, retry=now + delay)
        log(syslog.LOG_ERR, f"could not send \"{item['title']}\" to {name}, "
                            f"retrying in {duration(delay)}: {error}")
        pending.append(item)
    return pending[-QUEUE_MAX:]


def prepare():
    """Settings and enabled channels, or None when switched off or unreadable."""
    config = load_config()
    if config is None:
        return None
    general = config["general"]
    if general.get("enabled", "0") != "1":
        return None
    channels = [c for c in config["channels"] if c.get("enabled", "0") == "1"]
    return config, general, channels, config["hostname"]


def run_check():
    prepared = prepare()
    if prepared is None:
        # disabled, not merely unreadable: start from a fresh baseline when enabled again
        if os.path.exists(STATE) and load_config() is not None:
            os.remove(STATE)
        return
    config, general, channels, hostname = prepared
    prune_key_files(config["channels"])
    events = {e for c in channels for e in c["events"]}
    state = fresh_state()
    new_state, messages = {"stamp": int(time.time())}, []
    for event, collector in COLLECTORS:
        if event not in events:
            continue  # dropped, so subscribing later starts from a baseline
        try:
            new_state[event], found = collector(config, state.get(event))
        except Exception as exc:
            log(syslog.LOG_ERR, f"{event} check failed: {exc}")
            new_state[event], found = state.get(event), []
        messages.extend(found)
    if is_carp_backup(config):
        new_state["queue"] = state.get("queue", [])  # standby; the master reports
        save_state(new_state)
        return
    try:
        threshold = int(general.get("digestFrom", "0"))
    except ValueError:
        threshold = 0
    new_state["queue"] = send(channels, title_prefix(general, hostname), messages,
                              state.get("queue", []), threshold)
    save_state(new_state)


def run_boot():
    prepared = prepare()
    if prepared is None:
        return
    config, general, channels, hostname = prepared
    if is_carp_backup(config):
        return
    state = fresh_state()
    try:
        version = subprocess.run(["/usr/local/sbin/opnsense-version", "-v"], capture_output=True,
                                 text=True, timeout=30).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        version = ""
    body = f"Running OPNsense {version}." if version else ""
    found = [message("boot", "info", "Firewall has started", body)]
    state["queue"] = send(channels, title_prefix(general, hostname), found, state.get("queue", []))
    state["stamp"] = int(time.time())
    save_state(state)


def run_status():
    config = load_config() or {"general": {}, "channels": []}
    general, channels = config["general"], config["channels"]
    names = {c["uuid"]: c.get("description", c["uuid"]) for c in channels}
    state = load_state()
    now = int(time.time())
    queued = [{
        "title": item.get("title", ""),
        "channel": names.get(item.get("uuid"), item.get("uuid", "")),
        "event": item.get("event", ""),
        "age": duration(now - item.get("time", now)),
        "tries": item.get("tries", 0),
        "retry_in": duration(item.get("retry", now) - now),
    } for item in state.get("queue", [])]
    return {
        "enabled": general.get("enabled", "0") == "1",
        "checked": clock(state["stamp"]) if state.get("stamp") else "",
        "age": duration(now - state["stamp"]) if state.get("stamp") else "",
        "channels": len([c for c in channels if c.get("enabled", "0") == "1"]),
        "events": sorted({e for c in channels if c.get("enabled", "0") == "1" for e in c["events"]}),
        "queued": queued,
    }


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
        return {"status": "ok"}
    log(syslog.LOG_ERR, f"could not send test notification to {name}: {error}")
    return {"status": "failed", "message": error}


# ------------------------------------------------------------------ channel URLs
# the settings page builds a channel URL from fields generated out of Apprise's own
# service details, so new or changed services need no plugin changes


def apprise_services():
    """Apprise services keyed by id, with a lookup from every schema to the id."""
    import apprise
    services: dict = {}
    schemas: dict = {}
    for entry in apprise.Apprise().details()["schemas"]:
        protocols = list(entry.get("secure_protocols") or []) + list(entry.get("protocols") or [])
        templates = [str(t) for t in entry["details"]["templates"]]
        if not protocols or not templates:
            continue
        keys: list[list[str]] = [re.findall(r"{(\w+)}", template) for template in templates]
        used = {key for form in keys for key in form}
        # what a service needs at minimum: its shortest URL form, anything Apprise marks
        # required, and where the notification goes; the rest are extras
        basic = set(sorted(keys, key=len)[0])
        tokens = {}
        for key, token in entry["details"]["tokens"].items():
            if key not in used:
                continue  # e.g. target_user, an alternative spelling of targets
            kind = str(token.get("type", "string"))
            field = {"key": key, "label": str(token.get("name", key)), "type": kind.split(":")[0],
                     "private": bool(token.get("private")),
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
        args = {str(k): v.get("default") for k, v in entry["details"]["args"].items()
                if v.get("default") is not None and not v.get("alias_of")}
        mapped = {t["map_to"] for t in tokens.values()}
        options = {}
        for key, arg in entry["details"]["args"].items():
            if arg.get("alias_of") or key in tokens or str(arg.get("map_to", key)) in mapped:
                continue  # already a field
            kind = str(arg.get("type", "string"))
            field = {"key": str(key), "label": str(arg.get("name", key)), "type": kind.split(":")[0],
                     "private": bool(arg.get("private")), "basic": False}
            # an optional secret is never shown again, so the dialog offers to remove it instead
            field["clearable"] = field["private"]
            if kind.startswith("choice"):
                # Apprise hands some over as a set; numbers sort as numbers
                field["values"] = sorted(
                    (str(v) for v in arg.get("values", ())),
                    key=lambda v: (not v.lstrip("-").isdigit(),
                                   int(v) if v.lstrip("-").isdigit() else v))
            if arg.get("default") is not None:
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
        services[service_id] = {"id": service_id, "name": str(entry["service_name"]),
                                "setup": str(entry.get("setup_url") or ""), "templates": templates,
                                "tokens": tokens, "args": args, "options": options, "prefixes": prefixes}
        for protocol in protocols:
            schemas.setdefault(protocol.lower(), service_id)

    # options nearly every service has are Apprise's own, so they sort last; its per-send
    # retry is the exception, dropped because it would fight the queue's own backoff
    shared: dict = {}
    for service in services.values():
        for key in service["options"]:
            shared[key] = shared.get(key, 0) + 1
    for service in services.values():
        for key in list(service["options"]):
            if key in ("retry", "wait"):
                del service["options"][key]
            else:
                service["options"][key]["common"] = shared[key] >= 0.9 * len(services)
    return services, schemas


def default_text(value):
    """An Apprise default as field text; some are enums, some bools."""
    value = getattr(value, "value", value)
    return ("yes" if value else "no") if isinstance(value, bool) else str(value)


def url_schema(url):
    return url.split("://", 1)[0].lower() if "://" in url else ""


def parse_saved(url, services, schemas):
    """(service id, {map_to: value}, query) for a saved URL, or (None, {}, "")."""
    from apprise.plugins import N_MGR
    service_id = schemas.get(url_schema(url))
    if service_id is None:
        return None, {}, ""
    plugin = N_MGR[url_schema(url)] if url_schema(url) in N_MGR else None
    results = plugin.parse_url(url) if plugin is not None else None
    query = urllib.parse.urlsplit(url).query
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
    plugins = [check_url(url)[0] for url in (first, second)]
    return None not in plugins and plugins[0].url(privacy=False) == plugins[1].url(privacy=False)


def run_services():
    services, _ = apprise_services()
    result = []
    for service in sorted(services.values(), key=lambda s: s["name"].lower()):
        fields = sorted(service["tokens"].values(), key=lambda f: f["key"] != "schema")
        if len(fields) and fields[0]["key"] == "schema" and len(fields[0].get("values", [])) < 2:
            fields = fields[1:]  # nothing to choose
        fields += sorted(service["options"].values(), key=lambda f: (f["common"], f["label"].lower()))
        result.append({"id": service["id"], "name": service["name"], "setup": service["setup"],
                       "fields": [{k: v for k, v in f.items() if k not in ("map_to", "common")}
                                  for f in fields]})
    return result


def run_describe(uuid):
    return describe_url(saved_url(uuid))


def same_value(value, default):
    """Does a URL parameter say the same as its default? Apprise renders bools as yes/no."""
    value = str(value).strip().lower()
    if isinstance(default, bool):
        return value in (("yes", "true", "1") if default else ("no", "false", "0", ""))
    return value == default_text(default).strip().lower()


def split_query(service, query):
    """A URL's query as (option field values, whatever no field covers)."""
    values, rest = {}, []
    for part in (query or "").split("&"):
        key, _, value = part.partition("=")
        if key in service["options"]:
            values[key] = urllib.parse.unquote_plus(value)
        elif part:
            rest.append(part)
    return values, "&".join(rest)


def query_from(service, values):
    """The query for a service's option fields, leaving out anything at its default."""
    parts = []
    for key, field in service["options"].items():
        value = str(values.get(key, "")).strip()
        default = service["args"].get(key)
        if field["type"] == "bool":
            if value == "":
                continue
            value = "yes" if value.lower() in ("1", "yes", "true", "on") else "no"
            if default is None and value == "no":
                continue  # an unticked box Apprise has no default for says nothing
        if value == "" or (default is not None and same_value(value, default)):
            continue
        parts.append("%s=%s" % (urllib.parse.quote(key, safe=""), urllib.parse.quote(value, safe="")))
    rest = str(values.get(QUERY_FIELD, "")).lstrip("?")
    return "&".join([part for part in parts + [rest] if part])


def normalize(url, plugin, services, schemas):
    """A URL in a scheme the fields do not know, rewritten in Apprise's own form."""
    if url_schema(url) in schemas:
        return url
    native = plugin.url(privacy=False)
    service_id = schemas.get(url_schema(native))
    if service_id is None:
        return url
    base, _, query = native.partition("?")
    args = services[service_id]["args"]
    # what the same URL renders with nothing set is the service's own defaults
    plain, _ = check_url(base)
    defaults = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(plain.url(privacy=False)).query)) \
        if plain is not None else {}
    keep = []
    for part in query.split("&"):
        key, _, value = part.partition("=")
        value = urllib.parse.unquote(value)
        if key in defaults and value == defaults[key]:
            continue
        if key in args and same_value(value, args[key]):
            continue
        keep.append(part)  # only what differs from the service's own defaults
    return base + ("?" + "&".join(keep) if keep else "")


def run_parse(path):
    """Fields for a URL the user pasted, so the dialog can fill itself in."""
    try:
        with open(path) as handle:
            url = str(json.load(handle).get("url") or "").strip()
    except (OSError, ValueError):
        return {"error": "The request could not be read."}
    if not url:
        return {"error": "Enter an Apprise URL to import."}
    plugin, error = check_url(url)
    if plugin is None:
        return {"error": error}
    services, schemas = apprise_services()
    url = normalize(url, plugin, services, schemas)
    described = describe_url(url, keep_secrets=True)
    if not described.get("service"):
        described["error"] = ("The fields cannot represent this URL exactly, so it is kept as it is. "
                              "Save it as a custom URL.")
    return described


def describe_url(url, keep_secrets=False):
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
    options, rest = split_query(service, urllib.parse.urlsplit(url).query)
    if any(urllib.parse.unquote(part).startswith(service["prefixes"]) for part in rest.split("&")):
        return {"service": "", "custom": True}  # no field masks these, so keep the URL write-only
    for key, value in options.items():
        (secrets if service["options"][key]["private"] else fields)[key] = value
    if rest:
        fields[QUERY_FIELD] = rest
    if keep_secrets:
        fields.update(secrets)  # pasted by the user a moment ago, so no point hiding them
    # a URL the fields cannot reproduce stays a plain URL, so saving never changes it
    values = {**fields, **secrets}
    rebuilt = compose(service, values)[0]
    query = query_from(service, values)
    if rebuilt is None or not same_url(rebuilt + ("?" + query if query else ""), url):
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
                value = value.lstrip("/")  # the template carries the separator
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


def check_url(url):
    """(apprise plugin, error text) for a URL."""
    import apprise
    local = local_file_args(url)
    if local:
        return None, (f"The URL names a file in {', '.join(local)}; choose the service and paste the "
                      f"file's contents instead.")
    with apprise.LogCapture(level=apprise.logging.WARNING, fmt="%(message)s") as captured:
        try:
            plugin = apprise.Apprise.instantiate(url)
        except Exception:
            plugin = None  # a plugin tripping over the URL still means a bad URL
        errors = [line for line in captured.getvalue().splitlines() if line.strip()]
    if plugin is None:
        return None, errors[-1] if errors else "This is not a valid Apprise URL."
    return plugin, ""


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
        stored_options, _ = split_query(service, urllib.parse.urlsplit(stored).query)
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
            continue  # fetched from that address
        if len(value) > KEY_MAX:
            return "", {}, f"The {service['options'][key]['label']} is larger than a key or template should be."
        files[key.lower()] = value.replace("\r\n", "\n") + ("" if value.endswith("\n") else "\n")
        values[key] = KEY_MARKER
    url, wanted = compose(service, values)
    if url is None:
        needed = ", ".join(wanted) if wanted else "the fields this service needs"
        return "", {}, f"Fill in {needed}; see the setup guide if you are unsure."
    query = query_from(service, values)
    return (url + "?" + query if query else url), files, ""


def run_build(path):
    try:
        with open(path) as handle:
            request = json.load(handle)
    except (OSError, ValueError):
        return {"error": "The request could not be read.", "field": "channel.url"}
    uuid = str(request.get("uuid") or "")
    channel = saved_channel(uuid)
    stored = channel.get("url", "")
    service_id = str(request.get("service") or "")
    fields = {str(k): str(v).strip() for k, v in (request.get("fields") or {}).items()}

    files: dict = {}
    if service_id and (fields.get("changed") == "1" or not stored):
        url, files, error = from_service(service_id, fields, stored)
        target_field = "apprise_service"
    else:
        url = str(request.get("url") or "").strip() or stored
        error = "" if url else "Enter an Apprise URL or choose a service."
        target_field = "channel.url"
    if error:
        return {"error": error, "field": target_field}

    plugin, error = check_url(url)
    if plugin is None:
        return {"error": error, "field": target_field}
    masked = plugin.url(privacy=True).split("?", 1)[0]
    # keep the stored files the URL still points at, with anything newly pasted on top
    kept = {key: value for key, value in (channel.get("files") or {}).items() if key in stored_file_args(url)}
    kept.update(files)
    missing = [key for key in stored_file_args(url) if key not in kept]
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
    elif len(sys.argv) > 2 and sys.argv[1] == "test":
        print(json.dumps(run_test(sys.argv[2])))
    elif len(sys.argv) > 1 and sys.argv[1] == "services":
        print(json.dumps(run_services()))
    elif len(sys.argv) > 2 and sys.argv[1] == "describe":
        print(json.dumps(run_describe(sys.argv[2])))
    elif len(sys.argv) > 2 and sys.argv[1] == "parse":
        print(json.dumps(run_parse(sys.argv[2])))
    elif len(sys.argv) > 2 and sys.argv[1] == "build":
        print(json.dumps(run_build(sys.argv[2])))
    else:
        print(f"usage: {sys.argv[0]} check | boot | status | test <uuid> | services | "
              f"describe <uuid> | parse <file> | build <file>",
              file=sys.stderr)
        sys.exit(1)
