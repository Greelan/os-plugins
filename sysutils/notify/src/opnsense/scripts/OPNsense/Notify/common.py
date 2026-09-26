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
FIRMWARE = "/tmp/pkg_upgrade.json"
CONFIGCTL = "/usr/local/sbin/configctl"
PFCTL = "/sbin/pfctl"
SYSCTL = "/sbin/sysctl"
# running: a wireless access point
LINK_UP = ("active", "associated", "running")


def log(priority, message):
    syslog.syslog(priority, message)


def configctl_json(*args):
    """JSON from a configd action, or None; a missing action is a plugin bug, so say so.

    PHP renders an empty array as [], so an empty answer comes back as {}.
    """
    output = command_output([CONFIGCTL] + list(args), timeout=120)
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


def clip(text, limit):
    return text if len(text) <= limit else text[:limit - 1] + "…"


def read_firmware():
    """The last firmware check's result, or None."""
    try:
        with open(FIRMWARE) as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def setting(general, key, default):
    """An integer setting, or default when it is unset or unreadable."""
    try:
        return int(general.get(key, default))
    except ValueError:
        return default


@functools.lru_cache(maxsize=1)
def ifconfig():
    return command_output(["/sbin/ifconfig", "-a"])


def carp_states():
    """CARP states of every virtual IP on this firewall."""
    return re.findall(r"^\s+carp: (\S+) vhid", ifconfig() or "", re.M)


def addresses():
    """Device -> the addresses it holds, link-local and loopback aside."""
    found: dict = {}
    device = None
    for line in (ifconfig() or "").splitlines():
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


def link_states(names):
    """Carrier per configured interface that reports one."""
    found, device = {}, None
    for line in (ifconfig() or "").splitlines():
        match = re.match(r"^(\S+): flags=", line)
        if match:
            device = match.group(1)
            continue
        match = re.match(r"^\s+status: (.+)$", line)
        if match is not None and device in names:
            found[device] = match.group(1).strip()
    return found


@functools.lru_cache(maxsize=1)
def pf_states():
    """(entries, limit) of the state table, or None; read once per run."""
    info, limits = command_output([PFCTL, "-si"]), command_output([PFCTL, "-sm"])
    if info is None or limits is None:
        return None
    found = re.search(r"current entries\s+(\d+)", info)
    allowed = re.search(r"states\s+hard limit\s+(\d+)", limits)
    return (int(found.group(1)), int(allowed.group(1)) if allowed else 0) if found else None


def size(octets):
    units = ("B", "kB", "MB", "GB", "TB")
    index = 0
    while octets >= 1000 and index < len(units) - 1:
        octets /= 1000
        index += 1
    return f"{octets:.0f} B" if index == 0 else f"{octets:.1f} {units[index]}"
