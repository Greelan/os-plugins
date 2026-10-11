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

Helpers shared by the notify backend's checks and summaries: running commands and
configd actions, formatting, and reading interfaces, CARP, the firmware check and pf's
state table.
"""

import functools
import json
import os
import re
import subprocess
import syslog
import time

MENTION = re.compile(r"@(?=[\w&])")  # as Apprise's Discord finds mentions
TITLE_MAX = 200
BODY_MAX = 4000
FACT_MAX = 200
CONFIGCTL = "/usr/local/sbin/configctl"
# running: a wireless access point
LINK_UP = ("active", "associated", "running")


def log(priority, message):
    syslog.syslog(priority, message)


def configctl(*args):
    """What a configd action printed, or None."""
    return command_output([CONFIGCTL] + list(args), timeout=120)


def configctl_json(*args):
    """JSON from a configd action, or None; a missing action is a plugin bug, so say so.

    PHP renders an empty array as [], so an empty answer comes back as {}.
    """
    output = configctl(*args)
    try:
        answer = json.loads(output or "")
        return {} if answer == [] else answer
    except ValueError:
        log(syslog.LOG_DEBUG, f"no usable answer from \"{' '.join(args)}\": {(output or '')[:100].strip()}")
        return None


def command_output(command, timeout=30, partial=False):
    """What a command printed, or None if it failed; with partial, even so."""
    try:
        # e.g. a stray byte in an interface description
        result = subprocess.run(command, capture_output=True, text=True, errors="replace", timeout=timeout)
    except (OSError, subprocess.SubprocessError):
        return None
    return result.stdout if result.returncode == 0 or partial else None


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


def message(event, ntype, title, body, facts=None):
    """A notification; facts are tallied in summaries. Text is clipped, as it may come from outside."""
    # a notification with an empty body is refused on delivery, so fall back to the title
    title = str(title) if title not in (None, "") else event  # e.g. an IDS alert with no signature
    found = {"event": event, "type": ntype, "title": clip(title, TITLE_MAX), "body": clip(str(body or title), BODY_MAX),
             "time": int(time.time())}
    if facts:
        found["facts"] = {key: clip(str(value), FACT_MAX) for key, value in facts.items() if value}
    return found


def write_private(path, content, only_changed=False):
    """A root-only file, replaced atomically; with only_changed, left alone if unchanged."""
    folder = os.path.dirname(path)
    if folder:
        os.makedirs(folder, mode=0o700, exist_ok=True)
        if os.stat(folder).st_mode & 0o077:
            os.chmod(folder, 0o700)
    if only_changed:
        try:
            with open(path) as current:
                if current.read() == content:
                    return
        except OSError:
            pass
    tmp = f"{path}.{os.getpid()}.tmp"
    try:
        os.unlink(tmp)  # a leftover of this pid's name
    except OSError:
        pass
    try:
        handle = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(handle, "w") as stream:
            stream.write(content)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def quiet(text):
    """Text with Discord mentions broken, e.g. a login name of @everyone, so it pings no one."""
    return MENTION.sub("@\u200b", text)


def stale_tmp(path):
    """A temporary file an interrupted write left, rather than one being written."""
    try:
        return time.time() - os.stat(path).st_mtime > 3600
    except OSError:
        return False


def prune_stale(folder):
    """Remove the temporary files interrupted writes left in a folder."""
    try:
        names = os.listdir(folder)
    except OSError:
        return
    for name in names:
        if name.endswith(".tmp") and stale_tmp(os.path.join(folder, name)):
            try:
                os.unlink(os.path.join(folder, name))
            except OSError:
                pass


def clip(text, limit):
    return text if len(text) <= limit else text[:limit - 1] + "…"


@functools.lru_cache(maxsize=1)
def system_status():
    """System Status's items that are not OK, {name: item}, or None; read once per run."""
    data = configctl_json("system", "status")
    return data if isinstance(data, dict) else None


@functools.lru_cache(maxsize=1)
def firmware_product():
    """Core's firmware product details, the last update check among them, or {}."""
    data = configctl_json("firmware", "product")
    return data if isinstance(data, dict) else {}


# the Firmware page's lists, and how it names each change
FIRMWARE_CHANGES = (("upgrade_packages", "upgrade"), ("new_packages", "new"), ("reinstall_packages", "reinstall"),
                    ("downgrade_packages", "downgrade"), ("remove_packages", "obsolete"))


def firmware_changes(check):
    """[(key, line, reason)] for each package change a firmware check found."""
    found = []
    for field, reason in FIRMWARE_CHANGES:
        for p in check.get(field) or []:
            name = p.get("name")
            if field in ("upgrade_packages", "downgrade_packages"):
                version = p.get("new_version")
                line = f"{name} {p.get('current_version')} -> {version}"
            else:
                version = p.get("version")
                line = f"{name} {version}"
            # upgrades and new ones keep the key they had, so a change seen before is not sent again
            key = f"{name}-{version}" if reason in ("upgrade", "new") else f"{name}-{version} {reason}"
            found.append((key, line if reason == "upgrade" else f"{line} ({reason})", reason))
    return found


def read_firmware():
    """The last firmware check's result, or None."""
    check = firmware_product().get("product_check")
    return check if isinstance(check, dict) else None


def setting(general, key, default):
    """An integer setting, or default when it is unset or unreadable."""
    try:
        return int(general.get(key, default))
    except (TypeError, ValueError):
        return default


@functools.lru_cache(maxsize=1)
def service_states():
    """Services as the Services widget shows them, [(key, label, running)], or None if unreadable;
    those core does not check always read as running, so are left out."""
    services = configctl_json("service", "list")
    if services == {}:
        return []  # PHP's empty list
    if not isinstance(services, list):
        return None
    found: list = []
    seen: dict = {}
    for s in services:
        if not isinstance(s, dict) or s.get("nocheck"):
            continue
        key = f"{s.get('name', '')}/{s.get('id', '')}"
        seen[key] = seen.get(key, 0) + 1
        # a name repeated without an id stays apart
        found.append((key if seen[key] == 1 else f"{key}#{seen[key]}", str(s.get("description") or s.get("name") or "?"),
                      "is running" in str(s.get("status", ""))))
    return found


@functools.lru_cache(maxsize=1)
def interfaces():
    """Devices as core reads them from ifconfig, {device: details}, or None if unreadable."""
    data = configctl_json("interface", "list", "ifconfig")
    return data if isinstance(data, dict) and data else None


def carp_vhids():
    """[(device, vhid, state)] of every CARP virtual IP on this firewall."""
    found = []
    for device, details in (interfaces() or {}).items():
        carp = details.get("carp") or {}
        for entry in carp.values() if isinstance(carp, dict) else carp:
            found.append((device, str(entry.get("vhid", "")), str(entry.get("status", ""))))
    return found


def carp_states():
    """CARP states of every virtual IP on this firewall."""
    return [state for _, _, state in carp_vhids()]


@functools.lru_cache(maxsize=1)
def temporary_addresses():
    """IPv6 privacy addresses, which rotate. Core's listing carries no flag for them, so ifconfig is
    read for that one, as core's own scripts read it where the listing falls short
    (filter/lib/alias/interface.py, dnsmasq/get_dnsmasq_leases.py)."""
    found = set()
    for line in (command_output(["/sbin/ifconfig"]) or "").splitlines():
        parts = line.split()
        if parts[:1] == ["inet6"] and "temporary" in parts:
            found.add(parts[1].partition("%")[0])
    return found


def addresses():
    """Device -> the addresses it holds, link-local, loopback, deprecated and temporary aside."""
    found: dict = {}
    temporary = temporary_addresses()
    for device, details in (interfaces() or {}).items():
        for entry in (details.get("ipv4") or []) + (details.get("ipv6") or []):
            address = str(entry.get("ipaddr", ""))
            if address and not entry.get("link-local") and not entry.get("deprecated") \
                    and not address.startswith(("127.", "::1")) and address not in temporary:
                found.setdefault(device, []).append(address)
    return found


def link_states(names):
    """Carrier per configured interface that reports one."""
    return {device: str(details["status"]).strip() for device, details in (interfaces() or {}).items()
            if device in names and details.get("status")}


@functools.lru_cache(maxsize=1)
def pf_states():
    """(entries, limit) of the state table, as the dashboard's Firewall States widget reads it
    ("current N", "limit N"), or None; read once per run."""
    values = dict(line.split(None, 1) for line in (configctl("filter", "diag", "state_size") or "").splitlines()
                  if len(line.split()) == 2)
    try:
        return int(values["current"]), int(values.get("limit", 0))
    except (KeyError, ValueError):
        return None


def size(octets):
    units = ("B", "kB", "MB", "GB", "TB")
    index = 0
    while octets >= 1000 and index < len(units) - 1:
        octets /= 1000
        index += 1
    return f"{octets:.0f} B" if index == 0 else f"{octets:.1f} {units[index]}"
