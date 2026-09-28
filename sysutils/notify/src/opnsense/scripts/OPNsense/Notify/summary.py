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

Daily, weekly and monthly summaries per channel: the period's events and pf counters,
the report as text and as HTML with graphs, and core's health data read for the graphs.
"""

import atexit
import base64
import calendar
import datetime
import hashlib
import html
import json
import math
import os
import re
import shutil
import syslog
import tempfile
import time

from chart import AREA_SHADE, GRAPH_SIZE, PIE_COLORS, PIE_OTHER, PIE_SIZE, chart_png, day_marks, donut_png
from common import (FIRMWARE, LINK_UP, PFCTL, SYSCTL, addresses, carp_states, clock, command_output,
                    configctl_json, duration, link_states, log, message, pf_states, read_firmware, setting,
                    size, stale_tmp, write_private)


# ------------------------------------------------------------------ summaries
# a period counts its channel's events and adds up pf's counters; no logs are read


SUMMARY_RECENT = 10
SUMMARY_RULES = 5
# values kept per fact; the rarest go
FACTS_MAX = 100
# event: (section title, [(fact, column)])
FACT_SECTIONS = {
    "ids": ("Intrusion detection", [("signature", "Signature"), ("source", "Source")]),
    "auth": ("Logins", [("outcome", "Outcome"), ("user", "User"), ("source", "Source")]),
    "vpn": ("VPN peers", [("peer", "Change")]),
    "syslog": ("Critical log messages", [("program", "Program")]),
}
# counter reads; resets between are seen from rule loads and interface clearing
SAMPLE_SECONDS = 300
# builds tried before a period is dropped
SUMMARY_TRIES = 5
RRDTOOL = "/usr/local/bin/rrdtool"
RRD_DIR = "/var/db/rrd"
# interfaces graphed per section, by the Summary graphs setting; None is all
GRAPH_INTERFACES = {"none": 0, "top1": 1, "top3": 3, "all": None}
# rewritten on each rule load
RULESET = "/tmp/rules.debug"
# per channel, as Sophos UTM keeps
REPORTS_DIR = "/var/db/notify/reports"
REPORTS_KEEP = {"daily": 60, "weekly": 52, "monthly": 12}
REPORTS_MANUAL = 10  # sent by hand, per channel
REPORT_NAME = re.compile(r"([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})-(daily|weekly|monthly)(-now)?"
                         r"-(\d{8}-\d{6})\.html")
GRAPHS: dict = {}  # drawn once per run, by spec
# on top of the inline styles, for readers that take a style sheet: no text boosting (a phone
# otherwise enlarges some blocks and not others, even captions), a narrow screen stacks a pie
# over its table, and dark mode
TEXT_AS_IS = "-webkit-text-size-adjust:100%;text-size-adjust:100%"
# apart, as Gmail drops a whole style block over one rule it does not take
SCHEME_STYLE = ":root{color-scheme:light dark;supported-color-schemes:light dark}"
REPORT_STYLE = f"""html,body,.nr{{{TEXT_AS_IS}}}
@media (max-width:540px){{
.nr .pie,.nr .rows{{display:block!important;width:auto!important}}
.nr .pie{{padding:0 0 8px!important}}
.nr .label{{padding-right:12px!important}}
.mail{{margin:0!important}}
}}
@media (prefers-color-scheme:dark){{
.nr,.nr h2,.nr h3{{color:#e8e8e8!important}}
.nr h3{{border-color:#444!important}}
.nr h4,.nr th,.nr .muted{{color:#b0b0b0!important}}
.nr th{{border-color:#555!important}}
.nr .late{{color:#e0a040!important}}
}}"""
# kind: (RRD file, unit, [(label, sources, factor, color, filled)]); bytes shown as bits
GRAPH_KINDS: dict = {
    "traffic": ("{key}-traffic.rrd", "bits", [("In", ("inpass", "inpass6"), 8, "#4e79a7", True),
                                              ("Out", ("outpass", "outpass6"), 8, "#e15759", False)]),
    "blocks": ("{key}-packets.rrd", "packets", [("In", ("inblock", "inblock6"), 1, "#e15759", True),
                                                ("Out", ("outblock", "outblock6"), 1, "#76b7b2", False)]),
    "cpu": ("system-processor.rrd", "percent", [("Busy", ("user", "nice", "system", "interrupt"), 1, "#4e79a7", True)]),
    "states": ("system-states.rrd", "states", [("States", ("pfstates",), 1, "#59a14f", True)]),
}


def summary_channels(channels):
    return [c for c in channels if c.get("summary", "none") != "none"]


def subscribed(channels):
    """Events some channel takes, as they happen or in its summary."""
    events = {e for c in channels for e in c["events"]}
    return events | {e for c in summary_channels(channels) for e in c.get("summaryEvents", [])}


def monit_allowed(channel, item):
    """A Monit alert passes the channel's Monit services filter, if it has one."""
    names = channel.get("monit") or []
    return not (item["event"] == "monit" and names and item.get("service") not in names)


def in_summary(channel, item):
    return item["event"] in channel.get("summaryEvents", []) and monit_allowed(channel, item)


def add_events(period, channel, messages):
    """The period with the channel's summary events counted."""
    # notes are not events; count stands for repeats
    items = [m for m in messages if in_summary(channel, m) and not m.get("note")]
    if not items:
        return period
    counts = dict(period.get("events", {}))
    for item in items:
        counts[item["event"]] = counts.get(item["event"], 0) + item.get("count", 1)
    recent = period.get("recent", []) + [{"time": m["time"], "title": m["title"]} for m in items if not m.get("quiet")]
    facts = {event: {key: dict(values) for key, values in kinds.items()}
             for event, kinds in period.get("facts", {}).items()}
    for item in items:
        for key, value in item.get("facts", {}).items():
            tally = facts.setdefault(item["event"], {}).setdefault(key, {})
            tally[value] = tally.get(value, 0) + item.get("count", 1)
            if len(tally) > 2 * FACTS_MAX:
                kept = sorted(tally.items(), key=lambda kv: -kv[1])[:FACTS_MAX]
                tally.clear()
                tally.update(kept)
    return dict(period, events=counts, recent=recent[-SUMMARY_RECENT:], facts=facts)


def pf_interfaces():
    """pf's totals per interface and when each was cleared, from core's reading; None if unreadable."""
    data = configctl_json("filter", "diag", "info", "interfaces")
    interfaces = data.get("interfaces") if isinstance(data, dict) else None
    if not isinstance(interfaces, dict):
        return None
    found: dict = {}
    cleared: dict = {}
    for device, values in interfaces.items():
        if not isinstance(values, dict):
            continue
        if values.get("cleared"):
            cleared[device] = str(values["cleared"])
        for key in ("in_pass", "in_block", "out_pass", "out_block"):
            way, action = key.split("_")
            names = [f"{way}{v}_{action}" for v in (4, 6)]
            if any(f"{n}_packets" in values for n in names):
                try:
                    counts = [sum(int(values.get(f"{n}_{unit}", 0)) for n in names) for unit in ("packets", "bytes")]
                except (TypeError, ValueError):
                    continue  # an odd value costs only this counter
                found.setdefault(device, {})[key] = counts
    return (found, cleared) if found else None


def pf_block_rules():
    """Packets per block rule label, and its load as "pid/rules"; None if unreadable."""
    output = command_output([PFCTL, "-sr", "-v"])
    if output is None:
        return None
    found: dict = {}
    loads: dict = {}
    expanded: dict = {}
    label = None
    for line in output.splitlines():
        line = line.strip()
        if not line.startswith("["):
            match = re.search(r'label "([^"]+)"', line)
            label = match.group(1) if match and line.startswith("block") else None
            if label:
                expanded[label] = expanded.get(label, 0) + 1
            continue
        packets = re.search(r"Packets:\s+(\d+)", line)
        loaded = re.search(r"Inserted:.*\bpid\s+(\d+)", line)
        if label and packets and "Evaluations" in line:
            found[label] = found.get(label, 0) + int(packets.group(1))  # one rule can expand to several
        elif label and loaded:
            loads.setdefault(label, loaded.group(1))
    loads = {label: f"{loads.get(label, '')}/{count}" for label, count in expanded.items()}
    return (found, loads) if output.strip() else None  # a firewall always has rules


def sample_counters(devices, rules):
    """pf's totals as flat counters, with rule loads and interface clearings (None if unreadable)."""
    sample = {}
    interfaces = pf_interfaces() if devices else ({}, {})
    for device, totals in (interfaces[0] if interfaces else {}).items():
        if device not in devices:
            continue  # groups and interfaces not assigned
        for key, (packets, octets) in totals.items():
            sample[f"if {device} {key} packets"] = packets
            sample[f"if {device} {key} bytes"] = octets
    found = pf_block_rules() if rules else ({}, {})
    counts, loads = found if found else ({}, {})
    for label, packets in counts.items():
        if packets:
            sample[f"rule {label}"] = packets
    return (sample,
            {label: loads[label] for label in counts if counts[label] and label in loads} if found else None,
            interfaces[1] if interfaces else None)


def counter_growth(previous, current, reset=(), rules=True, shrunk=()):
    """Growth per counter since the last sample. A drop is a reset, as are those in reset, unless in
    shrunk; a new counter is a baseline, except a new rule's."""
    if previous is None:
        return {}
    grown = {}
    for key, value in current.items():
        rule = key.startswith("rule ")
        last = None if key in reset else previous.get(key)
        if last is None and key not in previous and not (rule and rules):
            continue
        if last is not None and value < last and key in shrunk:
            continue
        grown[key] = value - last if last is not None and value >= last else value
    return {key: value for key, value in grown.items() if value}


def shown(key, sections):
    """Whether a channel's summary sections show this counter."""
    if key.startswith("rule ") or "_block " in key:
        return "firewall" in sections
    return "traffic" in sections


def boot_seconds(text):
    """When the system started, from sysctl's kern.boottime, or None."""
    found = re.search(r"sec = (\d+)", text or "")
    return int(found.group(1)) if found else None


def boot_time():
    return boot_seconds(command_output([SYSCTL, "-n", "kern.boottime"]))


def ruleset_stamp():
    try:
        return os.stat(RULESET).st_mtime_ns
    except OSError:
        return None


def last_boundary(now, schedule, hour, day, date=1):
    """The latest scheduled time at or before now; a monthly date past the month's end is its last
    day."""
    local = datetime.datetime.fromtimestamp(now)
    if schedule == "monthly":
        def monthly(year, month):
            last = calendar.monthrange(year, month)[1]
            return datetime.datetime(year, month, min(date, last), hour)
        moment = monthly(local.year, local.month)
        if moment > local:
            moment = monthly(local.year - (local.month == 1), (local.month - 2) % 12 + 1)
        return int(moment.timestamp())
    # fold=0: a repeated hour's first pass, so it is not due twice
    moment = local.replace(hour=hour, minute=0, second=0, microsecond=0, fold=0)
    if moment > local:
        moment -= datetime.timedelta(days=1)
    if schedule == "weekly":
        moment -= datetime.timedelta(days=(moment.isoweekday() - day) % 7)
    return int(moment.timestamp())


def schedule(general):
    """(hour, weekday, day of month), clamped to valid values."""
    hour, day, date = (setting(general, "summaryHour", 7), setting(general, "summaryDay", 1),
                       setting(general, "summaryDate", 1))
    return min(max(hour, 0), 23), min(max(day, 1), 7), min(max(date, 1), 31)


def standby_periods(config, channels, previous, now):
    """The periods a CARP standby keeps: those not yet due."""
    hour, day, date = schedule(config["general"])
    periods = (previous or {}).get("channels") or {}
    return {c["uuid"]: periods[c["uuid"]] for c in summary_channels(channels)
            if c["uuid"] in periods and periods[c["uuid"]].get("schedule") == c["summary"]
            and periods[c["uuid"]].get("since", now) >= last_boundary(now, c["summary"], hour, day, date)}


def update_summaries(config, channels, previous, messages, now):
    """Count events and counters into each channel's period: (new state, channels due)."""
    previous = previous or {}
    wanted = summary_channels(channels)
    if not wanted:
        return {}, []
    hour, day, date = schedule(config["general"])
    old = previous.get("channels") or {}
    boundaries = {c["uuid"]: last_boundary(now, c["summary"], hour, day, date) for c in wanted}
    due_now = any(old.get(c["uuid"], {}).get("since", now) < boundaries[c["uuid"]] for c in wanted)
    # a new period starts from a fresh reading
    opening = any(old.get(c["uuid"], {}).get("schedule") != c["summary"] for c in wanted)
    sections = {s for c in wanted for s in c.get("summarySections", [])}
    health = "health" in sections
    states = pf_states() if health else None
    load = os.getloadavg()[0] if health else 0
    reading = {"load": load} if health else {}
    if states is not None:
        reading.update(states=states[0], statesLimit=states[1])
    if not due_now and not opening and previous.get("counters") is not None \
            and now - previous.get("sampled", 0) < SAMPLE_SECONDS:
        grown: dict = {}
        state = {key: previous[key] for key in ("counters", "loads", "cleared", "rules", "ruleset", "boot",
                                                "sampled") if key in previous}
    else:
        grown, state = sample_growth(config, sections, previous)
        state["sampled"] = now

    def new_period(channel):
        return {"since": now, "schedule": channel["summary"], "totals": {}, "peaks": dict(reading)}

    periods, due = {}, []
    for channel in wanted:
        period = old.get(channel["uuid"])
        opened = period is None or period.get("schedule") != channel["summary"]
        if period is None or opened:
            period = new_period(channel)
        totals = dict(period.get("totals", {}))
        for key, value in ({} if opened else grown).items():
            if shown(key, channel.get("summarySections", [])):
                totals[key] = totals.get(key, 0) + value
        peaks = dict(period.get("peaks", {}))
        if health:
            peaks["load"] = max(peaks.get("load", 0), load)
        if states is not None and states[0] >= peaks.get("states", 0):
            peaks.update(states=states[0], statesLimit=states[1])
        period = add_events(dict(period, totals=totals, peaks=peaks), channel, messages)
        if period["since"] < boundaries[channel["uuid"]] <= now:
            due.append((channel, period))
            # this reading also opens the next period
            period = new_period(channel)
        periods[channel["uuid"]] = period
    return dict(state, channels=periods), due


def sample_growth(config, sections, previous):
    """Read pf's counters: (growth, reading to keep)."""
    devices = set(config.get("interfaces", {})) if sections & {"firewall", "traffic"} else set()
    sample, loads, cleared = sample_counters(devices, "firewall" in sections)
    before = previous.get("counters") or {}
    # pf unreadable: keep the last reading
    if loads is None:
        sample.update({k: v for k, v in before.items() if k.startswith("rule ")})
        loads = previous.get("loads") or {}
    if cleared is None:
        sample.update({k: v for k, v in before.items() if k.startswith("if ")})
        cleared = previous.get("cleared") or {}
    ruleset = ruleset_stamp()
    # cleared, e.g. by a reboot
    was = previous.get("cleared") or {}
    reset = {key for key in sample if key.startswith("if ")
             and was.get(key.split()[1], cleared.get(key.split()[1])) != cleared.get(key.split()[1])}
    # resets: without Keep counters, a new pfctl pid (or rules.debug) per load; with it, a drop
    # unless the label lost pf rules, or a reboot
    kept = bool(config.get("keepCounters"))
    boot = (boot_time() or previous.get("boot")) if kept else None
    loaded = previous.get("loads") or {}
    shrunk: set = set()

    def pid_of(load):
        return str(load).partition("/")[0]

    def rules_of(load):
        count = str(load).partition("/")[2]
        return int(count) if count.isdigit() else None

    if kept and previous.get("boot") is not None and boot != previous.get("boot"):
        reset |= {key for key in sample if key.startswith("rule ")}
    elif kept:
        shrunk = {f"rule {label}" for label, load in loads.items()
                  if None not in (rules_of(load), rules_of(loaded.get(label)))
                  and rules_of(load) < rules_of(loaded.get(label))}
    elif any(pid_of(load) for load in loads.values()):
        reset |= {f"rule {label}" for label, load in loads.items()
                  if pid_of(loaded.get(label, load)) != pid_of(load)}
    elif ruleset != previous.get("ruleset"):
        reset |= {key for key in sample if key.startswith("rule ")}
    grown = counter_growth(previous.get("counters"), sample, reset, previous.get("rules", False), shrunk)
    return grown, {"counters": sample, "loads": loads, "cleared": cleared, "rules": "firewall" in sections,
                   "ruleset": ruleset, "boot": boot}


def system_health():
    """Uptime, memory and disk lines for a summary."""
    lines = []
    output = command_output([SYSCTL, "kern.boottime", "hw.physmem", "vm.stats.vm.v_page_count",
                             "vm.stats.vm.v_free_count", "vm.stats.vm.v_inactive_count",
                             "vm.stats.vm.v_laundry_count", "kstat.zfs.misc.arcstats.size"],
                            partial=True) or ""  # the ZFS name is missing on UFS
    values = dict(line.split(": ", 1) for line in output.splitlines() if ": " in line)
    booted = boot_seconds(values.get("kern.boottime"))
    if booted:
        lines.append(f"Up {duration(time.time() - booted)}")
    try:
        pages = int(values["vm.stats.vm.v_page_count"])
        idle = sum(int(values.get(f"vm.stats.vm.v_{kind}_count", 0)) for kind in ("free", "inactive", "laundry"))
        arc = int(values.get("kstat.zfs.misc.arcstats.size", 0))
        # as the dashboard
        lines.append(f"Memory {(pages - idle) * 100 // max(pages, 1)}% used of {size(int(values['hw.physmem']))}"
                     + (f", ZFS cache {size(arc)}" if arc else ""))
    except (KeyError, ValueError):
        pass
    try:
        disk = os.statvfs("/")
        used = disk.f_blocks - disk.f_bfree
        # as df
        percent = -(-used * 100 // max(used + disk.f_bavail, 1))
        lines.append(f"Disk {percent}% used of {size(disk.f_blocks * disk.f_frsize)}")
    except OSError:
        pass
    return lines


def current_status(config, now):
    """Status lines: uplink addresses, gateways, links, services, CARP, firmware, certificates."""
    names, lines = config.get("interfaces", {}), []
    held = addresses()
    disabled = set(config.get("disabled", []))
    # IPv4 first
    for device in [d for d in config.get("uplinks", []) if d not in disabled]:
        lines.append(f"{names.get(device, device)} address: {', '.join(sorted(held.get(device, []), key=lambda a: (':' in a, a))) or 'none'}")
    gateways = configctl_json("interface", "gateways", "status")
    for name, gateway in (gateways.items() if isinstance(gateways, dict) else []):
        # ~ is no reading
        detail = ", ".join([str(gateway.get("status_translated") or gateway.get("status", ""))] + [
            f"{label} {gateway[key]}" for key, label in (("delay", "RTT"), ("loss", "loss"))
            if gateway.get(key, "~") not in ("~", "")])
        lines.append(f"Gateway {name}: {detail}")
    links = {d: s for d, s in link_states(names).items() if d not in disabled}
    down = [f"{names[d]} {s}" for d, s in links.items() if s not in LINK_UP]
    if links:
        lines.append(f"Links down: {', '.join(down)}" if down else f"{len(links)} of {len(links)} interface links up")
    services = configctl_json("service", "list")
    # as the Services widget; those core does not check always read as running
    checked = [s for s in services if isinstance(s, dict) and not s.get("nocheck")] \
        if isinstance(services, list) else []
    stopped = [str(s.get("description") or s.get("name", "?")) for s in checked
               if "is running" not in str(s.get("status", ""))]
    if stopped:
        listed = ", ".join(f"{n} ({stopped.count(n)})" if stopped.count(n) > 1 else n for n in sorted(set(stopped)))
        lines.append(f"Services: {len(checked) - len(stopped)} of {len(checked)} running; stopped: {listed}")
    elif checked:
        lines.append(f"{len(checked)} of {len(checked)} services running")
    carp = carp_states()
    if carp:
        lines.append(f"CARP: {', '.join(f'{carp.count(s)} {s}' for s in sorted(set(carp)))}")
    firmware = read_firmware()
    try:
        checked = clock(os.stat(FIRMWARE).st_mtime)
    except OSError:
        firmware = None
    if firmware is not None and firmware.get("connection") != "ok":
        lines.append(f"Firmware: The last update check failed (checked {checked})")
    elif firmware is not None:
        pending = len(firmware.get("upgrade_packages") or []) + len(firmware.get("new_packages") or [])
        major = firmware.get("upgrade_major_version") or ""
        found = ", ".join(filter(None, [f"{pending} update(s) pending" if pending else "",
                                         f"{major} available" if major else ""])) or "Up to date"
        lines.append(f"Firmware: {found} (checked {checked})")
    else:
        # e.g. after a reboot, as it lives in /tmp, or while a check rewrites it
        lines.append("Firmware: No update check result")
    days = setting(config["general"], "certDays", 14)
    for item in sorted(config.get("certificates", []), key=lambda c: c["expires"]):
        left = item["expires"] - now
        if -days * 86400 < left <= days * 86400:
            state = "expired" if left <= 0 else f"expires in {left // 86400} day(s)"
            lines.append(f"{item['label']} {item['description']} {state}")
    return lines


def brief_status(lines):
    """The status for the short text: first address, gateways counted, three certificates."""
    shown: list = []
    certificates: list = []
    troubled: list = []
    online, at = 0, None
    for line in lines:
        label, _, value = line.partition(": ")
        if label.startswith("Gateway "):
            at = len(shown) if at is None else at
            state = re.split(r", (?:RTT|loss) ", value)[0]
            if state == "Online":
                online += 1
            else:
                troubled.append(f"{label[len('Gateway '):]} {state}")
            continue
        if label.endswith(" address") and ", " in value:
            first, *rest = value.split(", ")
            line = f"{label}: {first} (+{len(rest)})"
        if line.startswith(("Certificate ", "Authority ")):
            certificates.append(line)
            continue
        shown.append(line)
    if at is not None:
        shown.insert(at, "Gateways: " + "; ".join(([f"{online} online"] if online else []) + troubled))
    shown += certificates[:3]
    if len(certificates) > 3:
        shown.append(f"and {len(certificates) - 3} more certificates")
    return shown


def build_summary(config, channel, period, now, shared=None):
    """A channel's summary: a short text body, and the report as sections for email or attachment.
    shared holds parts common to channels."""
    shared = {} if shared is None else shared

    def once(key, compute):
        if key not in shared:
            shared[key] = compute()
        return shared[key]

    names, keys = config.get("interfaces", {}), config.get("ifnames", {})
    choice = config.get("general", {}).get("summaryGraphs")
    graphed = GRAPH_INTERFACES.get(choice, GRAPH_INTERFACES["top3"])
    reporting = config.get("healthReporting", True)
    graphing = reporting and graphed != 0
    totals, peaks = period.get("totals", {}), period.get("peaks", {})
    sections = channel.get("summarySections", [])
    title = f"{period.get('schedule', channel['summary']).capitalize()} summary"
    span = f"{clock(period['since'])} to {clock(now)}"
    host = config.get("hostname", "")
    report: list = []
    brief: list = []  # a line per section, for plain text

    def section(heading, head=None, sub=False):
        """A report part; a sub part belongs to the one before."""
        report.append({"title": heading, "head": head, "rows": [], "graphs": [], "sub": sub})
        return report[-1]

    def color(index):
        """A row's color, in its pie and its graph."""
        return PIE_COLORS[index] if index < len(PIE_COLORS) else PIE_OTHER

    def pie(part, name, values, rest=False):
        """A donut of the rows; with rest, the last is gray."""
        if sum(values) <= 0 or len(values) < 2:
            return
        colors = [color(i) for i in range(len(values))]
        if rest:
            colors[-1] = PIE_OTHER
        part["swatches"] = colors
        part["pie"] = {"kind": "pie", "name": f"pie-{name}.png", "title": part["title"],
                       "slices": [[v, c] for v, c in zip(values, colors) if v > 0],
                       "start": period["since"], "end": now}

    def row(part, cells):
        """A row; text splits at its first colon."""
        part["rows"].append(cells.split(": ", 1) if isinstance(cells, str) else cells)

    def graph_key(device):
        """The name core keeps a device's health data under, if usable."""
        key = keys.get(device, "") if device else "system"
        return key if re.fullmatch(r"[A-Za-z0-9_]+", key) else None

    def busiest(devices):
        """Those to graph: the busiest that have health data, up to the setting."""
        return [d for d in devices if graph_key(d)][:graphed]

    def graph(part, kind, device, heading, hue=None):
        if not graphing:
            return
        key = graph_key(device)
        if key:
            part["graphs"].append({"kind": kind, "key": key, "title": heading, "name": f"{kind}-{key}.png",
                                   "start": period["since"], "end": now, **({"color": hue} if hue else {})})

    if "status" in sections:
        part = section("Current status")
        status = once("status", lambda: current_status(config, now))
        for line in status:
            row(part, line)
        brief.append(" · ".join(brief_status(status)))

    if channel.get("summaryEvents"):
        counts, recent = period.get("events", {}), period.get("recent", [])
        part = section("Events in the period", ["Event", "Count"])
        if not counts:
            row(part, ["None"])
        listed = []
        for event, count in sorted(counts.items(), key=lambda kv: -kv[1]):
            label = config.get("eventLabels", {}).get(event, event)
            row(part, [label, f"{count:,}"])
            listed.append(f"{count:,} {label}")
        brief.append("Events: " + (", ".join(listed) or "none"))
        if recent:
            part = section(f"Latest {len(recent)} of {sum(counts.values())}", ["Time", "Event"], True)
            for item in recent:
                row(part, [clock(item["time"]), item["title"]])
        for event in [e for e in FACT_SECTIONS if e in channel.get("summaryEvents", [])]:
            heading, kinds = FACT_SECTIONS[event]
            for key, label in kinds:
                tally = period.get("facts", {}).get(event, {}).get(key, {})
                if not tally:
                    continue
                part = section(f"{heading}: top {label.lower()}s" if len(kinds) > 1 else heading, [label, "Count"],
                               True)
                for value, count in sorted(tally.items(), key=lambda kv: -kv[1])[:SUMMARY_RULES]:
                    row(part, [value, f"{count:,}"])

    by_key: dict = {}
    for name, value in totals.items():
        parts = name.split()
        if parts[0] == "if":
            by_key.setdefault(f"{parts[2]} {parts[3]}", {})[parts[1]] = value

    if "firewall" in sections:
        part = section("Firewall blocks", ["Interface", "Packets in", "Packets out", "Size"])
        packets_in, packets_out = by_key.get("in_block packets", {}), by_key.get("out_block packets", {})
        bytes_in, bytes_out = by_key.get("in_block bytes", {}), by_key.get("out_block bytes", {})
        blocked = sorted(set(packets_in) | set(packets_out),
                         key=lambda d: -(packets_in.get(d, 0) + packets_out.get(d, 0)))
        if not blocked:
            row(part, ["None"])
        for device in blocked:
            octets = bytes_in.get(device, 0) + bytes_out.get(device, 0)
            name = names.get(device, device)
            row(part, [name, f"{packets_in.get(device, 0):,}", f"{packets_out.get(device, 0):,}", size(octets)])
        each = [(names.get(d, d), packets_in.get(d, 0) + packets_out.get(d, 0)) for d in blocked]
        brief.append(f"Blocked: {sum(n for _, n in each):,} packets"
                     + (f" ({', '.join(f'{name} {n:,}' for name, n in each[:3])})" if len(each) > 1 else ""))
        pie(part, "blocks", [packets_in.get(d, 0) + packets_out.get(d, 0) for d in blocked])
        for device in busiest(blocked):
            graph(part, "blocks", device, f"{names.get(device, device)} blocked", color(blocked.index(device)))
        every = sorted(((k.split(" ", 1)[1], v) for k, v in totals.items() if k.startswith("rule ")),
                       key=lambda kv: -kv[1])
        rules, rest = every[:SUMMARY_RULES], sum(v for _, v in every[SUMMARY_RULES:])
        if rules:
            described = once("rules", lambda: {
                r.get("id"): r.get("descr") for r in configctl_json("filter", "list", "rule_ids") or []
                if isinstance(r, dict)})
            part = section("Block rules matched most", ["Rule", "Packets"], True)
            for label, packets in rules:
                row(part, [described.get(label) or label, f"{packets:,}"])
            if rest:
                row(part, ["Other rules", f"{rest:,}"])
            brief.append(f"Most blocks: {described.get(rules[0][0]) or rules[0][0]} ({rules[0][1]:,})")
            pie(part, "rules", [packets for _, packets in rules] + ([rest] if rest else []), rest=bool(rest))

    if "traffic" in sections:
        part = section("Traffic", ["Interface", "In", "Out"])
        received, sent = by_key.get("in_pass bytes", {}), by_key.get("out_pass bytes", {})
        devices = sorted(set(received) | set(sent), key=lambda d: -(received.get(d, 0) + sent.get(d, 0)))
        if not devices:
            row(part, ["None recorded"])
        for device in devices:
            row(part, [names.get(device, device), size(received.get(device, 0)), size(sent.get(device, 0))])
        for device in busiest(devices):
            graph(part, "traffic", device, f"{names.get(device, device)} traffic", color(devices.index(device)))
        brief.append("Traffic: " + (" · ".join(f"{names.get(d, d)} {size(received.get(d, 0))} in, "
                                                f"{size(sent.get(d, 0))} out" for d in devices[:3]) or "none recorded"))
        pie(part, "traffic", [received.get(d, 0) + sent.get(d, 0) for d in devices])

    if "health" in sections:
        part = section("System")
        health = list(once("health", system_health))
        load = os.getloadavg()[0]
        health.append(f"Load {load:.2f}, peak {max(peaks.get('load', 0), load):.2f}")
        if peaks.get("states") is not None:
            limit = peaks.get("statesLimit") or 0
            share = f" of {limit:,} ({peaks['states'] * 100 // limit}%)" if limit else ""
            health.append(f"State table peak {peaks['states']:,}{share}")
        for line in health:
            row(part, line)
        brief.append("System: " + " · ".join(health))
        graph(part, "cpu", None, "Processor")
        graph(part, "states", None, "State table")

    body = "\n".join([f"{host} · {span}" if host else span] + brief)
    note = "" if reporting or graphed == 0 or not {"firewall", "traffic", "health"} & set(sections) else \
        "No graphs: health reporting is off, under Reporting: Health."
    return dict(message("summary", "info", title, body), uuid=channel["uuid"],
                report={"title": title, "host": host, "span": span, "sections": report, "note": note})


def report_page(report, drawn, embed=True):
    """The report as a page: graphs in it, or with embed off, by reference for email."""
    title = html.escape(" · ".join(filter(None, [report["title"], report.get("host")])))
    return (f'<!doctype html>\n<html><head><meta charset="utf-8"><title>{title}</title>'
            f'<meta name="viewport" content="width=device-width, initial-scale=1">'
            f'<meta name="color-scheme" content="light dark"><style>{SCHEME_STYLE}</style>'
            f'<style>{REPORT_STYLE}</style></head>'
            # a phone's mail app pads the message itself
            f'<body{"" if embed else MAIL_CLASS} style="margin:16px;{TEXT_AS_IS}">'
            f'{summary_html(report, drawn, embed)}</body></html>\n')


def archive_report(report, uuid, schedule, when, manual=False):
    """Archive a summary; the oldest beyond the limit go. Its name, for the link to it."""
    name = f"{uuid}-{schedule}{'-now' if manual else ''}-{time.strftime('%Y%m%d-%H%M%S', time.localtime(when))}.html"
    write_private(os.path.join(REPORTS_DIR, name), report_page(report, report_graphs(report)))
    kept, limit = 0, REPORTS_MANUAL if manual else REPORTS_KEEP.get(schedule, 0)
    for found in sorted(archived_reports(), key=lambda r: r["when"], reverse=True):
        if found["channel"] == uuid and found["manual"] == manual and (manual or found["schedule"] == schedule):
            kept += 1
            if kept > limit:
                remove_report(found["name"])
    return name


def prune_archive(channels):
    """Remove the archived summaries of channels that no longer exist, and interrupted writes."""
    for found in archived_reports():
        if found["channel"] not in channels:
            remove_report(found["name"])
    try:
        names = os.listdir(REPORTS_DIR)
    except OSError:
        return
    for name in names:
        if name.endswith(".tmp") and stale_tmp(os.path.join(REPORTS_DIR, name)):
            remove_report(name)


def remove_report(name):
    try:
        os.unlink(os.path.join(REPORTS_DIR, name))
    except OSError:
        pass


def archived_reports():
    """The archived pages: [{"name", "channel", "schedule", "manual", "when"}]."""
    try:
        names = os.listdir(REPORTS_DIR)
    except OSError:
        return []
    found = []
    for name in names:
        match = REPORT_NAME.fullmatch(name)
        if match:
            found.append({"name": name, "channel": match.group(1), "schedule": match.group(2),
                          "manual": bool(match.group(3)),
                          "when": time.mktime(time.strptime(match.group(4), "%Y%m%d-%H%M%S"))})
    return found


def report_graphs(report):
    """The graphs and pies a report shows, drawn: name -> {"path", ...}."""
    graphs = [spec for part in report["sections"]
              for spec in part.get("graphs", []) + ([part["pie"]] if part.get("pie") else [])]
    return {spec["name"]: graph for spec in graphs if (graph := drawn_graph(spec))}


def graph_dir():
    """This run's directory for graphs, removed when it ends."""
    if "dir" not in GRAPHS:
        # the heaviest part of a check: yield to the firewall
        try:
            os.nice(10)
        except OSError:
            pass
        GRAPHS["dir"] = tempfile.mkdtemp(prefix="notify-")
        atexit.register(shutil.rmtree, GRAPHS["dir"], True)
    return GRAPHS["dir"]


def drawn_graph(spec):
    """A graph, drawn once per run and spec."""
    key = json.dumps(spec, sort_keys=True)
    if key not in GRAPHS:
        folder = hashlib.sha1(key.encode()).hexdigest()[:16]
        GRAPHS[key] = draw_graph(spec, os.path.join(graph_dir(), folder))
    return GRAPHS[key]


def draw_graph(spec, directory):
    if spec["kind"] == "pie":
        os.makedirs(directory, exist_ok=True)
        path = os.path.join(directory, spec["name"])
        with open(path, "wb") as handle:
            handle.write(donut_png([(value, color) for value, color in spec["slices"]]))
        return {"path": path, "legend": []}  # its table is the legend
    return draw_series(spec, directory)


def draw_series(spec, directory):
    """A graph of core's health data, read with rrdtool fetch: {path, legend}, or None."""
    filename, unit, series = GRAPH_KINDS[spec["kind"]]
    rrd = os.path.join(RRD_DIR, filename.format(key=spec["key"]))
    if not os.path.isfile(rrd):
        log(syslog.LOG_WARNING, f"no {spec['title']} graph: {rrd} is missing; is health reporting on?")
        return None
    rows = rrd_fetch(rrd, int(spec["start"]), int(spec["end"]))
    if rows is None:
        log(syslog.LOG_WARNING, f"no {spec['title']} graph: {rrd} could not be read")
        return None
    lines = []
    for label, sources, factor, color, filled in series:
        # an interface's color from its pie: In as the area alone and Out as the line, as a
        # shade would fade on a light or a dark page, and dashes break up on spiky data
        color = spec.get("color") or color
        values = []
        for _, row in rows:
            known = [row[name] for name in sources if row.get(name) is not None]
            values.append(sum(known) * factor if known else None)
        lines.append((label, values, color, filled))
    if all(v is None for _, values, _, _ in lines for v in values):
        log(syslog.LOG_WARNING, f"no {spec['title']} graph: {rrd} has no data for the period")
        return None
    stamps = [stamp for stamp, _ in rows]
    os.makedirs(directory, exist_ok=True)
    path = os.path.join(directory, spec["name"])
    with open(path, "wb") as handle:
        handle.write(chart_png([(values, color, filled, "color" not in spec)
                                for _, values, color, filled in lines],
                               day_marks(stamps[0], stamps[-1])))
    return {"path": path, "legend": graph_legend(unit, lines, "color" in spec)}


def rrd_fetch(rrd, start, end):
    """[(time, {source: value or None})] from an RRD, or None."""
    output = command_output([RRDTOOL, "fetch", rrd, "AVERAGE", "-s", str(start), "-e", str(end)], timeout=60)
    lines = [line for line in (output or "").splitlines() if line.strip()]
    if len(lines) < 2:
        return None
    names = lines[0].split()
    rows = []
    for line in lines[1:]:
        stamp, sep, values = line.partition(":")
        if not sep or not stamp.strip().isdigit():
            continue
        row = {}
        for name, value in zip(names, values.split()):
            try:
                number = float(value)
            except ValueError:
                number = math.nan
            row[name] = number if math.isfinite(number) else None  # nan, or inf from a counter wrap
        rows.append((int(stamp), row))
    return rows if len(rows) > 1 else None


def rate(value, unit):
    if unit == "percent":
        return f"{value:.0f}%"
    if unit == "states":
        return f"{value:,.0f}"
    word = "bit/s" if unit == "bits" else "packets/s"
    for prefix in ("", "k", "M", "G"):
        if value < 1000 or prefix == "G":
            return f"{value:.0f} {word}" if not prefix else f"{value:.1f} {prefix}{word}"
        value /= 1000
    return ""


def graph_legend(unit, lines, areas=False):
    """[(label, color, figures, look)] per series with data; look is "line", "fill", or "area" for a
    fill without its outline."""
    legend = []
    for label, values, color, filled in lines:
        known = [v for v in values if v is not None]
        if known:
            look = ("area" if areas else "fill") if filled else "line"
            legend.append((label if len(lines) > 1 else "", color,
                           f"peak {rate(max(known), unit)}, average {rate(sum(known) / len(known), unit)}", look))
    return legend


LABEL_CLASS = ' class="label"'
MAIL_CLASS = ' class="mail"'


def graph_caption_html(title, graph):
    """Each series' figures after a swatch of it: a bar for a line, a square for an area, shaded as
    drawn when it has no outline."""
    legend = graph.get("legend") or []
    marks = {"line": ("&#9473;", ""), "fill": ("&#9632;", ""), "area": ("&#9632;", f";opacity:{AREA_SHADE}")}
    # a no-break space keeps each swatch with its label
    parts = [f'<span style="color:{html.escape(color)}{marks[look][1]}">{marks[look][0]}</span>&nbsp;'
             + html.escape(f"{label} {figures}" if label else figures) for label, color, figures, look in legend]
    return f"{html.escape(title)}: " + "; ".join(parts)


def summary_html(report, drawn, embed=False):
    """The report as HTML, every value escaped and styles inline; embed puts the graphs in the page."""

    def source(name):
        if not embed:
            return f"cid:{html.escape(name)}"
        with open(drawn[name]["path"], "rb") as handle:
            return "data:image/png;base64," + base64.b64encode(handle.read()).decode()
    font = "font-family:-apple-system,'Segoe UI',Helvetica,Arial,sans-serif"
    heading = "font-size:16px;margin:28px 0 8px;padding-bottom:4px;border-bottom:1px solid #d0d0d0;color:#222"
    subheading = "font-size:14px;margin:18px 0 6px;color:#444"
    th = "padding:4px 12px 4px 0;border-bottom:1px solid #c8c8c8;color:#555;font-weight:600;text-align:{}"
    # long values, e.g. IPv6 addresses, wrap rather than widen the page
    td = "padding:3px 12px 3px 0;vertical-align:top;overflow-wrap:anywhere;word-break:break-word;text-align:{}"
    out = [f'<div class="nr" style="{font};font-size:14px;color:#222;max-width:{GRAPH_SIZE[0]}px;{TEXT_AS_IS}">',
           f'<h2 style="font-size:20px;margin:0 0 2px">{html.escape(report["title"])}</h2>',
           f'<div class="muted" style="color:#666">'
           f'{html.escape(" · ".join(filter(None, [report.get("host"), report["span"]])))}</div>']
    if report.get("delayed"):
        out.append(f'<p class="late" style="color:#a15c00"><em>{html.escape(report["delayed"])}</em></p>')
    if report.get("note"):
        out.append(f'<p class="muted" style="color:#666"><em>{html.escape(report["note"])}</em></p>')
    for part in report["sections"]:
        style = subheading if part.get("sub") else heading
        tag = "h4" if part.get("sub") else "h3"
        out.append(f'<{tag} style="{style}">{html.escape(part["title"])}</{tag}>')
        width = max([len(r) for r in part["rows"]] + [1])
        numeric = [i > 0 and all(i >= len(r) or re.fullmatch(r"[\d,]+(\.\d+)?( \S+)?", str(r[i])) for r in part["rows"])
                   for i in range(width)]
        # a label and value table, e.g. Current status: labels kept on one line, but not a
        # line on its own, which would run off a narrow screen
        label = ";white-space:nowrap;padding-right:24px" if not part.get("head") else ""
        pie = part.get("pie")
        swatches = part.get("swatches", []) if pie and pie["name"] in drawn else []
        if swatches:
            out.append('<table style="border-collapse:collapse;width:100%"><tr>'
                       f'<td class="pie" style="width:{PIE_SIZE}px;vertical-align:top;padding:0 16px 0 0">'
                       f'<img src="{source(pie["name"])}" alt="{html.escape(pie["title"])}" '
                       f'width="{PIE_SIZE}" height="{PIE_SIZE}"></td><td class="rows" style="vertical-align:top;padding:0">')
        out.append('<table style="border-collapse:collapse;width:100%">')
        if part.get("head") and any(len(r) > 1 for r in part["rows"]):
            out.append("<tr>" + "".join(f'<th style="{th.format("right" if numeric[i] else "left")}">{html.escape(h)}</th>'
                                        for i, h in enumerate(part["head"])) + "</tr>")
        for number, cells in enumerate(part["rows"]):
            span = f' colspan="{width}"' if len(cells) == 1 and width > 1 else ""
            mark = (f'<span style="color:{html.escape(swatches[number])}">&#9632;</span>&nbsp;'
                    if number < len(swatches) else "")
            cells_html = []
            for i, c in enumerate(cells):
                labelled = bool(label) and i == 0 and len(cells) > 1
                cell_style = td.format("right" if numeric[i] else "left") + (label if labelled else "")
                cells_html.append(f'<td{LABEL_CLASS if labelled else ""} style="{cell_style}"{span}>'
                                  f'{mark if i == 0 else ""}{html.escape(str(c))}</td>')
            out.append("<tr>" + "".join(cells_html) + "</tr>")
        out.append("</table>")
        if swatches:
            out.append("</td></tr></table>")
        for spec in part.get("graphs", []):
            if spec["name"] in drawn:
                # its size given, so a phone lays it out right before the image loads
                out.append(f'<p style="margin:12px 0 0"><img src="{source(spec["name"])}" '
                           f'alt="{html.escape(spec["title"])}" width="{GRAPH_SIZE[0]}" height="{GRAPH_SIZE[1]}" '
                           f'style="display:block;width:100%;max-width:{GRAPH_SIZE[0]}px;height:auto">'
                           + (f'<small class="muted" style="display:block;margin-top:4px;color:#555;font-size:12px">{graph_caption_html(spec["title"], drawn[spec["name"]])}</small>'
                              if drawn[spec["name"]].get("legend") else "") + '</p>')
    out.append("</div>")
    return "\n".join(out)
