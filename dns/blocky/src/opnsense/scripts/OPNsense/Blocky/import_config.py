#!/usr/bin/env python3

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

Parse an upstream Blocky config.yml and map it to the OPNsense Blocky model
structure. Emits JSON on stdout:

  {
    "scalars": { "general": {...}, "dnssec": {...}, ... },
    "arrays":  { "upstreams": [ {...}, ... ], ... },
    "skipped": [ "<key>: <reason>", ... ],
    "warnings": [ "<message>", ... ]
  }

The mapping is the inverse of templates/OPNsense/Blocky/config.yml. The PHP
importer applies "scalars" via setNodes() and adds one row per "arrays" entry,
then relies on the model's own validation to reject bad values.

"skipped" lists valid blocky keys the plugin does not support. "warnings" covers
migrated deprecated keys, wrong shapes, unknown keys and dropped values.
"""

import json
import os
import re
import sys

# PyYAML is vendored under lib/ (pure-Python), so no pkg dependency is needed.
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "lib"))
try:
    import yaml
except ImportError:
    print(json.dumps({"error": "bundled PyYAML could not be loaded."}))
    sys.exit(0)

# YAML 1.1 boolean spellings, for values that reach us as quoted strings.
TRUTHY = ("y", "yes", "true", "on", "1")
FALSY = ("n", "no", "false", "off", "0")

# download settings blocky applies to the sources
DOWNLOAD_FIELDS = (
    ("timeout", "downloadTimeout"),
    ("attempts", "downloadAttempts"),
    ("cooldown", "downloadCooldown"),
    ("cachePath", "downloadCachePath"),
)

# blocky takes these from blocking.loading.downloads for its own HTTP server
SERVER_TIMEOUT_FIELDS = (
    ("writeTimeout", "downloadWriteTimeout"),
    ("readTimeout", "downloadReadTimeout"),
    ("readHeaderTimeout", "downloadReadHeaderTimeout"),
)

LOADING_KEYS = {"strategy", "concurrency", "maxErrorsPerSource", "refreshPeriod", "downloads"}
DOWNLOAD_KEYS = {"timeout", "readTimeout", "readHeaderTimeout", "writeTimeout",
                 "attempts", "cooldown", "cachePath"}

# blocky's config schema (yaml tags of its config package), to report keys the
# import does not take. User-named maps are checked where they are read.
SCHEMA = {
    "": {"upstreams", "connectIPVersion", "customDNS", "conditional", "blocking",
         "clientLookup", "caching", "queryLog", "prometheus", "statistics", "redis",
         "log", "ports", "minTlsServeVersion", "certFile", "keyFile", "bootstrapDns",
         "hostsFile", "fqdnOnly", "filtering", "ede", "ecs", "specialUseDomains",
         "dns64", "dnssec", "http3", "rateLimit", "rebindingProtection"},
    "ports": {"dns", "http", "https", "tls", "dohPath", "freeBind", "proxyProtocol"},
    "upstreams": {"init", "timeout", "groups", "strategy", "userAgent", "quic"},
    "upstreams.init": {"strategy"},
    "upstreams.quic": {"maxIdleTimeout", "keepAlivePeriod"},
    "log": {"level", "format", "privacy", "timestamp"},
    "blocking": {"denylists", "allowlists", "schedules", "listSchedules",
                 "clientGroupsBlock", "blockType", "blockTTL", "loading"},
    "blocking.loading": LOADING_KEYS,
    "blocking.loading.downloads": DOWNLOAD_KEYS,
    "hostsFile": {"sources", "hostsTTL", "filterLoopback", "loading"},
    "hostsFile.loading": LOADING_KEYS,
    "hostsFile.loading.downloads": DOWNLOAD_KEYS,
    "caching": {"minTime", "maxTime", "cacheTimeNegative", "maxItemsCount", "prefetching",
                "prefetchExpires", "prefetchThreshold", "prefetchMaxItemsCount", "exclude"},
    "queryLog": {"target", "type", "logRetentionDays", "creationAttempts",
                 "creationCooldown", "fields", "flushInterval", "ignore"},
    "queryLog.ignore": {"sudn", "domains"},
    "redis": {"address", "username", "password", "database", "required",
              "connectionAttempts", "connectionCooldown", "sentinelUsername",
              "sentinelPassword", "sentinelAddresses"},
    "customDNS": {"customTTL", "mapping", "zone", "filterUnmappedTypes", "rewrite",
                  "fallbackUpstream"},
    "conditional": {"mapping", "rewrite", "fallbackUpstream"},
    "clientLookup": {"clients", "upstream", "singleNameOrder"},
    "filtering": {"queryTypes"},
    "prometheus": {"enable", "path"},
    "statistics": {"enable"},
    "rateLimit": {"enable", "rate", "burst", "ipv4Prefix", "ipv6Prefix", "allowlist"},
    "rebindingProtection": {"enable", "allowedDomains"},
    "ecs": {"useAsClient", "forward", "ipv4Mask", "ipv6Mask"},
    "dnssec": {"validate", "trustAnchors", "maxChainDepth", "cacheExpirationHours",
               "maxNSEC3Iterations", "maxUpstreamQueries", "clockSkewToleranceSec"},
    "dns64": {"enable", "prefixes", "exclusionSet"},
    "specialUseDomains": {"enable", "rfc6762-appendixG"},
    "http3": {"enable"},
    "fqdnOnly": {"enable"},
    "ede": {"enable"},
}

# duration fields: blocky reads a unitless value as minutes, the model's masks want a unit
DURATION_FIELDS = {
    "general.timeout", "general.quicMaxIdleTimeout", "general.quicKeepAlivePeriod",
    "general.blockTTL", "general.refreshPeriod", "general.downloadTimeout",
    "general.downloadCooldown", "general.downloadWriteTimeout", "general.downloadReadTimeout",
    "general.downloadReadHeaderTimeout", "general.cacheMinTime", "general.cacheMaxTime",
    "general.cacheTimeNegative", "general.prefetchExpires", "general.customTTL",
    "queryLog.creationCooldown", "queryLog.flushInterval",
    "hostsFile.hostsTTL", "hostsFile.refreshPeriod", "hostsFile.downloadTimeout",
    "hostsFile.downloadCooldown", "redis.connectionCooldown",
}

SCHEDULE_KEYS = {"start", "end", "weekdays"}
BOOTSTRAP_KEYS = {"upstream", "ips", "resolvFile"}

# valid blocky keys with no equivalent in the plugin
UNSUPPORTED = {
    "ports.freeBind": "Linux-only, not applicable on FreeBSD.",
    "log.timestamp": "handled by syslog on OPNsense; blocky's own timestamp is always disabled.",
    "customDNS.fallbackUpstream": "no equivalent setting in the plugin.",
    "hostsFile.loading.downloads.writeTimeout": "blocky does not use it for hosts files.",
    "hostsFile.loading.downloads.readTimeout": "blocky does not use it for hosts files.",
    "hostsFile.loading.downloads.readHeaderTimeout": "blocky does not use it for hosts files.",
}

# deprecated key -> current key, mirroring blocky's own migrations
MOVES = (
    ("upstream", "upstreams.groups"),
    ("upstreamTimeout", "upstreams.timeout"),
    ("dohUserAgent", "upstreams.userAgent"),
    ("port", "ports.dns"),
    ("httpPort", "ports.http"),
    ("httpsPort", "ports.https"),
    ("tlsPort", "ports.tls"),
    ("logLevel", "log.level"),
    ("logFormat", "log.format"),
    ("logPrivacy", "log.privacy"),
    ("blocking.blackLists", "blocking.denylists"),
    ("blocking.whiteLists", "blocking.allowlists"),
    ("blocking.downloadTimeout", "blocking.loading.downloads.timeout"),
    ("blocking.downloadAttempts", "blocking.loading.downloads.attempts"),
    ("blocking.downloadCooldown", "blocking.loading.downloads.cooldown"),
    ("blocking.refreshPeriod", "blocking.loading.refreshPeriod"),
    ("blocking.processingConcurrency", "blocking.loading.concurrency"),
    ("blocking.startStrategy", "blocking.loading.strategy"),
    ("blocking.maxErrorsPerFile", "blocking.loading.maxErrorsPerSource"),
    ("hostsFile.refreshPeriod", "hostsFile.loading.refreshPeriod"),
)


class Mapper:
    def __init__(self, doc):
        self.doc = doc if isinstance(doc, dict) else {}
        self.scalars = {}
        self.arrays = {}
        self.skipped = []
        self.warnings = []

    # -- value helpers -----------------------------------------------------
    def _bool(self, value, label):
        """Map a YAML boolean, or a quoted YAML 1.1 spelling of one, to 1/0."""
        if value is None:
            return None
        if isinstance(value, bool):
            return "1" if value else "0"
        text = str(value).strip().lower()
        if text in TRUTHY:
            return "1"
        if text in FALSY:
            return "0"
        self.warnings.append("%s: %s is not a true/false value; not imported." % (label, value))
        return None

    def _scalar(self, value, label):
        """A single value destined for a text, numeric or option field."""
        if value is None:
            return None
        if isinstance(value, bool):
            self.warnings.append("%s: expected a value, got true/false; not imported." % label)
            return None
        if isinstance(value, (dict, list, tuple)):
            self.warnings.append("%s: expected a single value; not imported." % label)
            return None
        return str(value).strip()

    def _sequence(self, value, label):
        """Return value as a list; a lone scalar counts as a one-item list."""
        if value is None:
            return []
        if isinstance(value, (list, tuple)):
            return list(value)
        if isinstance(value, dict):
            self.warnings.append("%s: expected a list; not imported." % label)
            return []
        return [value]

    def _list(self, value, label):
        """Join a list into the comma separated form the model's list fields use.
        A scalar passes through unchanged: blocky accepts comma separated strings
        (e.g. blockType) and those are already in the target form."""
        if value is None:
            return None
        if isinstance(value, dict):
            self.warnings.append("%s: expected a list of values; not imported." % label)
            return None
        if not isinstance(value, (list, tuple)):
            # blocky trims each part, the model's list fields do not
            text = self._scalar(value, label)
            return None if text is None else re.sub(r"\s*,\s*", ",", text)
        items = []
        for item in value:
            text = self._scalar(item, label)
            if text is None or text == "":
                continue
            if "\n" in text or "\r" in text:
                self.warnings.append("%s: multi-line values cannot be stored in a list "
                                     "field; not imported." % label)
                continue
            if "," in text:
                self.warnings.append(
                    "%s: %s contains a comma, which separates list items; not imported." % (label, text))
                continue
            items.append(text)
        return ",".join(items) if items else None

    def _timeofday(self, value, label):
        """PyYAML's YAML 1.1 resolver reads an unquoted 22:00 as the integer 1320;
        blocky parses YAML 1.2, where it stays a string."""
        if isinstance(value, int) and not isinstance(value, bool):
            if 0 <= value <= 24 * 60:
                return "%02d:%02d" % divmod(value, 60)
            self.warnings.append("%s: %s is not a time of day; not imported." % (label, value))
            return None
        return self._scalar(value, label)

    def _as_mapping(self, value, label):
        if value is None:
            return {}
        if not isinstance(value, dict):
            self.warnings.append("%s: expected a mapping; not imported." % label)
            return {}
        return value

    # -- document helpers --------------------------------------------------
    def _get(self, *path):
        """Return doc[path[0]][path[1]]... or None if any level is missing."""
        node = self.doc
        for key in path:
            if not isinstance(node, dict) or key not in node:
                return None
            node = node[key]
        return node

    def _pop(self, path):
        """Remove and return the value at a dotted path."""
        parts = path.split(".")
        node = self._get(*parts[:-1]) if len(parts) > 1 else self.doc
        if not isinstance(node, dict):
            return None
        return node.pop(parts[-1], None)

    def _mapping(self, path):
        return self._as_mapping(self._get(*path.split(".")), path)

    def _put(self, section, field, value, label, transform=None):
        if value is None:
            return
        value = (transform or self._scalar)(value, label)
        if value is None:
            return
        if value.isdigit() and value != "0" and "%s.%s" % (section, field) in DURATION_FIELDS:
            self.warnings.append("%s: %s has no unit; imported as %sm, the way blocky reads it."
                                 % (label, value, value))
            value += "m"
        self.scalars.setdefault(section, {})[field] = value

    def _map(self, path, section, field, transform=None):
        self._put(section, field, self._get(*path.split(".")), path, transform)

    def _row(self, name, row, label):
        rows = self.arrays.setdefault(name, [])
        if row in rows:
            self.warnings.append("%s: duplicate entry; imported once." % label)
            return
        rows.append(row)

    # -- top level ---------------------------------------------------------
    def run(self):
        self._migrate()
        self._check_keys()
        self._general_ports()
        self._general_connect_tls()
        self._upstreams()
        self._bootstrap()
        self._blocking()
        self._caching()
        self._client_lookup()
        self._prometheus_log()
        self._custom_dns()
        self._conditional()
        self._query_log()
        self._redis()
        self._filtering()
        self._rebinding()
        self._rate_limit()
        self._toggles()
        self._hosts_file()
        self._ecs()
        self._dnssec()
        self._dns64()
        self._statistics()
        return {
            "scalars": self.scalars,
            "arrays": self.arrays,
            "skipped": self.skipped,
            "warnings": self.warnings,
        }

    # -- deprecated keys ---------------------------------------------------
    def _migrate(self):
        """Move deprecated keys as blocky does, replacement wins when both are set."""
        for old, new in MOVES:
            value = self._pop(old)
            if value is not None:
                self._migrate_set(old, new, value)
        # deprecated spelling of an unsupported key
        if self._pop("logTimestamp") is not None:
            self.skipped.append("logTimestamp: deprecated; %s" % UNSUPPORTED["log.timestamp"])
        verify = self._pop("startVerifyUpstream")
        if verify is not None:
            flag = self._bool(verify, "startVerifyUpstream")
            if flag is not None:
                self._migrate_set("startVerifyUpstream", "upstreams.init.strategy",
                                  "failOnError" if flag == "1" else "fast")
        no_ipv6 = self._pop("disableIPv6")
        if no_ipv6 is not None and self._bool(no_ipv6, "disableIPv6") == "1":
            self._migrate_set("disableIPv6", "filtering.queryTypes", ["AAAA"])
        fail_start = self._pop("blocking.failStartOnListError")
        if fail_start is not None and self._bool(fail_start, "blocking.failStartOnListError") == "1":
            self._migrate_set("blocking.failStartOnListError", "blocking.loading.strategy",
                              "failOnError")
        file_path = self._pop("hostsFile.filePath")
        if file_path is not None:
            self._migrate_set("hostsFile.filePath", "hostsFile.sources", [file_path])

    def _migrate_set(self, old, new, value):
        parts = new.split(".")
        if self._get(*parts) is not None:
            self.warnings.append(
                "%s: deprecated and %s is also set; the deprecated key was ignored." % (old, new))
            return
        node = self.doc
        for depth, key in enumerate(parts[:-1]):
            child = node.get(key)
            if child is None:
                child = {}
                node[key] = child
            elif not isinstance(child, dict):
                self.warnings.append("%s: expected a mapping; %s was not imported."
                                     % (".".join(parts[:depth + 1]), old))
                return
            node = child
        node[parts[-1]] = value
        self.warnings.append("%s: deprecated; imported as %s." % (old, new))

    # -- unmapped keys -----------------------------------------------------
    def _check_keys(self):
        for path, known in SCHEMA.items():
            parts = path.split(".") if path else []
            node = self._get(*parts) if parts else self.doc
            if node is None:
                continue
            if not isinstance(node, dict):
                self.warnings.append("%s: expected a mapping; not imported." % path)
                continue
            for key in node:
                full = "%s.%s" % (path, key) if path else str(key)
                if full in UNSUPPORTED:
                    self.skipped.append("%s: %s" % (full, UNSUPPORTED[full]))
                elif key not in known:
                    self.warnings.append("%s: not recognized; not imported." % full)

    # -- sections ----------------------------------------------------------
    def _general_ports(self):
        # Each protocol maps to a single listener list field accepting the full
        # Blocky ports syntax (port, :port, ip:port, [ipv6]:port).
        for yml_key, field in (("dns", "dnsPort"), ("http", "httpPort"),
                               ("tls", "tlsPort"), ("https", "httpsPort")):
            self._map("ports.%s" % yml_key, "general", field, self._list)
        self._map("ports.dohPath", "general", "dohPath")
        self._map("ports.proxyProtocol", "general", "proxyProtocol", self._list)

    def _general_connect_tls(self):
        self._map("connectIPVersion", "general", "connectIPVersion")
        self._map("minTlsServeVersion", "general", "minTlsServeVersion")
        self._map("certFile", "general", "certFile")
        self._map("keyFile", "general", "keyFile")
        self._map("http3.enable", "general", "http3", self._bool)

    def _upstreams(self):
        self._map("upstreams.strategy", "general", "strategy")
        self._map("upstreams.timeout", "general", "timeout")
        self._map("upstreams.init.strategy", "general", "initStrategy")
        self._map("upstreams.userAgent", "general", "userAgent")
        self._map("upstreams.quic.maxIdleTimeout", "general", "quicMaxIdleTimeout")
        self._map("upstreams.quic.keepAlivePeriod", "general", "quicKeepAlivePeriod")
        for group, servers in self._mapping("upstreams.groups").items():
            label = "upstreams.groups.%s" % group
            for server in self._sequence(servers, label):
                value = self._scalar(server, label)
                if value:
                    self._row("upstreams", {
                        "enabled": "1", "group": str(group), "server": value,
                    }, "%s: %s" % (label, value))

    def _bootstrap(self):
        boot = self._get("bootstrapDns")
        if boot is None:
            return
        # one entry or a list of them
        entries = [boot] if isinstance(boot, dict) else self._sequence(boot, "bootstrapDns")
        for entry in entries:
            if isinstance(entry, dict):
                for key in sorted(set(entry) - BOOTSTRAP_KEYS):
                    self.warnings.append("bootstrapDns.%s: not recognized; not imported." % key)
                path = self._scalar(entry.get("resolvFile"), "bootstrapDns.resolvFile")
                if path:
                    self._row("bootstrap", {"enabled": "1", "type": "resolvfile", "content": path}, "bootstrapDns: %s" % path)
                    if entry.get("upstream") is not None or entry.get("ips") is not None:
                        # blocky rejects this combination outright
                        self.warnings.append("bootstrapDns.resolvFile: blocky does not allow a resolv "
                                             "file and an upstream in one entry; imported as two rows.")
                upstream = self._scalar(entry.get("upstream"), "bootstrapDns.upstream")
                if upstream is None and path is None and entry.get("ips") is not None:
                    self.warnings.append("bootstrapDns.ips: no upstream in this entry; not imported.")
                if upstream:
                    row = {"enabled": "1", "type": "resolver", "content": upstream}
                    ips = self._list(entry.get("ips"), "bootstrapDns.ips")
                    if ips is not None:
                        row["ips"] = ips
                    self._row("bootstrap", row, "bootstrapDns: %s" % upstream)
                continue
            upstream = self._scalar(entry, "bootstrapDns")
            if upstream:
                self._row("bootstrap", {"enabled": "1", "type": "resolver", "content": upstream},
                          "bootstrapDns: %s" % upstream)

    def _inline_sources(self, value):
        """A denylist/allowlist source may be a URL/path (single line) or a YAML
        block with several inline entries; expand blocks into one row each."""
        out = []
        for line in value.splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                out.append(line)
        return out

    def _blocking(self):
        for yml_key, name in (("denylists", "denylists"), ("allowlists", "allowlists")):
            for group, sources in self._mapping("blocking.%s" % yml_key).items():
                label = "blocking.%s.%s" % (yml_key, group)
                for source in self._sequence(sources, label):
                    text = self._scalar(source, label)
                    if text is None:
                        continue
                    for one in self._inline_sources(text):
                        self._row(name, {
                            "enabled": "1", "group": str(group), "source": one,
                        }, "%s: %s" % (label, one))
        for client, groups in self._mapping("blocking.clientGroupsBlock").items():
            label = "blocking.clientGroupsBlock.%s" % client
            value = self._list(groups, label)
            if value is not None:
                self._row("clientgroups", {
                    "enabled": "1", "client": str(client), "groups": value,
                }, label)
        self._map("blocking.blockType", "general", "blockType", self._list)
        self._map("blocking.blockTTL", "general", "blockTTL")
        self._map("blocking.loading.refreshPeriod", "general", "refreshPeriod")
        self._map("blocking.loading.strategy", "general", "loadingStrategy")
        self._map("blocking.loading.maxErrorsPerSource", "general", "maxErrorsPerSource")
        self._map("blocking.loading.concurrency", "general", "loadingConcurrency")
        for yml_key, field in DOWNLOAD_FIELDS + SERVER_TIMEOUT_FIELDS:
            self._map("blocking.loading.downloads.%s" % yml_key, "general", field)
        self._schedules()

    def _schedules(self):
        schedules = self._mapping("blocking.schedules")
        # invert group -> [schedule names] into schedule name -> [groups]
        sched_groups = {}
        for group, names in self._mapping("blocking.listSchedules").items():
            label = "blocking.listSchedules.%s" % group
            for name in self._sequence(names, label):
                if str(name) not in schedules:
                    self.warnings.append("%s: there is no schedule named %s; the reference "
                                         "was not imported." % (label, name))
                    continue
                sched_groups.setdefault(str(name), []).append(str(group))
        for name, spec in schedules.items():
            label = "blocking.schedules.%s" % name
            spec = self._as_mapping(spec, label)
            for key in sorted(set(spec) - SCHEDULE_KEYS):
                self.warnings.append("%s.%s: not recognized; not imported." % (label, key))
            weekdays = self._list(spec.get("weekdays"), "%s.weekdays" % label) or ""
            if weekdays == "":
                # blocky requires weekdays too
                self.warnings.append("%s: no weekdays; not imported." % label)
                continue
            groups = sched_groups.get(str(name), [])
            if not groups:
                # the model needs a group, blocky allows an unused schedule
                self.warnings.append("%s: no list group uses this schedule; not imported." % label)
                continue
            start = self._timeofday(spec.get("start"), "%s.start" % label) or ""
            end = self._timeofday(spec.get("end"), "%s.end" % label) or ""
            if (start == "") != (end == ""):
                # both or neither, as blocky requires
                self.warnings.append("%s: a schedule needs both start and end, or neither; "
                                     "imported as all day." % label)
                start = end = ""
            self._row("schedules", {
                "enabled": "1",
                "name": str(name),
                "groups": ",".join(groups),
                "weekdays": weekdays,
                "start": start,
                "end": end,
            }, label)

    def _caching(self):
        self._map("caching.minTime", "general", "cacheMinTime")
        self._map("caching.maxTime", "general", "cacheMaxTime")
        self._map("caching.cacheTimeNegative", "general", "cacheTimeNegative")
        self._map("caching.maxItemsCount", "general", "maxItemsCount")
        self._map("caching.prefetching", "general", "prefetching", self._bool)
        self._map("caching.prefetchExpires", "general", "prefetchExpires")
        self._map("caching.prefetchThreshold", "general", "prefetchThreshold")
        self._map("caching.prefetchMaxItemsCount", "general", "prefetchMaxItemsCount")
        self._map("caching.exclude", "general", "cacheExclude", self._list)

    def _client_lookup(self):
        self._map("clientLookup.upstream", "general", "clientLookupUpstream")
        self._map("clientLookup.singleNameOrder", "general", "clientLookupOrder", self._list)
        for name, ips in self._mapping("clientLookup.clients").items():
            label = "clientLookup.clients.%s" % name
            value = self._list(ips, label)
            if value is not None:
                self._row("clientlookupclients", {
                    "enabled": "1", "name": str(name), "ips": value,
                }, label)

    def _prometheus_log(self):
        self._map("prometheus.enable", "general", "prometheus", self._bool)
        self._map("prometheus.path", "general", "prometheusPath")
        self._map("log.level", "general", "logLevel")
        self._map("log.format", "general", "logFormat")
        self._map("log.privacy", "general", "logPrivacy", self._bool)

    def _custom_dns(self):
        self._map("customDNS.customTTL", "general", "customTTL")
        self._map("customDNS.filterUnmappedTypes", "general", "filterUnmappedTypes", self._bool)
        for domain, ips in self._mapping("customDNS.mapping").items():
            label = "customDNS.mapping.%s" % domain
            value = self._list(ips, label)
            if value is not None:
                self._row("customdns", {
                    "enabled": "1", "domain": str(domain), "ip": value,
                }, label)
        for src, dst in self._mapping("customDNS.rewrite").items():
            label = "customDNS.rewrite.%s" % src
            value = self._scalar(dst, label)
            if value:
                self._row("customdnsrewrite", {
                    "enabled": "1", "fromDomain": str(src), "toDomain": value,
                }, label)
        self._map("customDNS.zone", "general", "customZone")

    def _conditional(self):
        self._map("conditional.fallbackUpstream", "general", "conditionalFallback", self._bool)
        for domain, resolver in self._mapping("conditional.mapping").items():
            label = "conditional.mapping.%s" % domain
            value = self._list(resolver, label)
            if value is not None:
                self._row("conditional", {
                    "enabled": "1", "domain": str(domain), "resolver": value,
                }, label)
        for src, dst in self._mapping("conditional.rewrite").items():
            label = "conditional.rewrite.%s" % src
            value = self._scalar(dst, label)
            if value:
                self._row("conditionalrewrite", {
                    "enabled": "1", "fromDomain": str(src), "toDomain": value,
                }, label)

    def _query_log(self):
        for field in ("type", "target", "logRetentionDays", "creationAttempts",
                      "creationCooldown", "flushInterval"):
            self._map("queryLog.%s" % field, "queryLog", field)
        self._map("queryLog.fields", "queryLog", "fields", self._list)
        self._map("queryLog.ignore.sudn", "queryLog", "ignoreSudn", self._bool)
        self._map("queryLog.ignore.domains", "queryLog", "ignoreDomains", self._list)

    def _redis(self):
        for field in ("address", "username", "password", "database",
                      "connectionAttempts", "connectionCooldown",
                      "sentinelUsername", "sentinelPassword"):
            self._map("redis.%s" % field, "redis", field)
        self._map("redis.required", "redis", "required", self._bool)
        self._map("redis.sentinelAddresses", "redis", "sentinelAddresses", self._list)

    def _filtering(self):
        self._map("filtering.queryTypes", "filtering", "queryTypes", self._list)

    def _rebinding(self):
        self._map("rebindingProtection.enable", "rebindingProtection", "enable", self._bool)
        self._map("rebindingProtection.allowedDomains", "rebindingProtection",
                  "allowedDomains", self._list)

    def _rate_limit(self):
        self._map("rateLimit.enable", "rateLimit", "enable", self._bool)
        for field in ("rate", "burst", "ipv4Prefix", "ipv6Prefix"):
            self._map("rateLimit.%s" % field, "rateLimit", field)
        self._map("rateLimit.allowlist", "rateLimit", "allowlist", self._list)

    def _toggles(self):
        self._map("fqdnOnly.enable", "fqdnOnly", "enable", self._bool)
        self._map("ede.enable", "ede", "enable", self._bool)
        self._map("specialUseDomains.enable", "specialUseDomains", "enable", self._bool)
        self._map("specialUseDomains.rfc6762-appendixG", "specialUseDomains", "rfc6762",
                  self._bool)

    def _hosts_file(self):
        self._map("hostsFile.sources", "hostsFile", "sources", self._list)
        self._map("hostsFile.hostsTTL", "hostsFile", "hostsTTL")
        self._map("hostsFile.filterLoopback", "hostsFile", "filterLoopback", self._bool)
        self._map("hostsFile.loading.refreshPeriod", "hostsFile", "refreshPeriod")
        self._map("hostsFile.loading.strategy", "hostsFile", "loadingStrategy")
        self._map("hostsFile.loading.maxErrorsPerSource", "hostsFile", "maxErrorsPerSource")
        self._map("hostsFile.loading.concurrency", "hostsFile", "concurrency")
        for yml_key, field in DOWNLOAD_FIELDS:
            self._map("hostsFile.loading.downloads.%s" % yml_key, "hostsFile", field)

    def _ecs(self):
        self._map("ecs.useAsClient", "ecs", "useAsClient", self._bool)
        self._map("ecs.forward", "ecs", "forward", self._bool)
        self._map("ecs.ipv4Mask", "ecs", "ipv4Mask")
        self._map("ecs.ipv6Mask", "ecs", "ipv6Mask")

    def _dnssec(self):
        self._map("dnssec.validate", "dnssec", "validate", self._bool)
        for field in ("maxChainDepth", "cacheExpirationHours", "maxUpstreamQueries",
                      "maxNSEC3Iterations", "clockSkewToleranceSec"):
            self._map("dnssec.%s" % field, "dnssec", field)
        self._map("dnssec.trustAnchors", "dnssec", "trustAnchors", self._list)

    def _dns64(self):
        self._map("dns64.enable", "dns64", "enable", self._bool)
        self._map("dns64.prefixes", "dns64", "prefix", self._list)
        self._map("dns64.exclusionSet", "dns64", "exclusionSet", self._list)

    def _statistics(self):
        self._map("statistics.enable", "statistics", "enable", self._bool)


def main():
    # exits are 0: configd's script_output discards stdout on a non-zero exit
    if len(sys.argv) != 2:
        print(json.dumps({"error": "usage: import_config.py <config.yml>"}))
        sys.exit(0)
    try:
        with open(sys.argv[1], "r", encoding="utf-8") as handle:
            doc = yaml.safe_load(handle)
    except UnicodeDecodeError:
        print(json.dumps({"error": "the file is not valid UTF-8 text."}))
        sys.exit(0)
    except OSError as exc:
        print(json.dumps({"error": "could not read the file: %s" % (exc.strerror or exc)}))
        sys.exit(0)
    except yaml.YAMLError as exc:
        print(json.dumps({"error": "invalid YAML: %s" % exc}))
        sys.exit(0)
    if doc is None:
        print(json.dumps({"error": "the file is empty."}))
        sys.exit(0)
    if not isinstance(doc, dict):
        print(json.dumps({"error": "top-level YAML is not a mapping."}))
        sys.exit(0)
    try:
        result = Mapper(doc).run()
    except Exception as exc:
        # never leave stdout empty
        print(json.dumps({"error": "could not map the configuration: %s: %s"
                                   % (type(exc).__name__, exc)}))
        sys.exit(0)
    print(json.dumps(result))


if __name__ == "__main__":
    main()
