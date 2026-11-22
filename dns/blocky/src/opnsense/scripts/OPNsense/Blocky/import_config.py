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
import stat
import sys

# PyYAML is vendored under lib/ (pure-Python, pinned in lib/VENDOR), so no pkg dependency is needed.
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "lib"))
try:
    import yaml
except ImportError:
    print(json.dumps({"error": "bundled PyYAML could not be loaded."}))
    sys.exit(0)

# the web interface hands the file over in its tmp (AppConfig tempDir); only such a file is read
TEMP_DIR = "/var/lib/php/tmp"
TEMP_PREFIX = "blocky_import_"
IMPORT_MAX = 4 * 1024 * 1024

# YAML 1.1 boolean spellings, for values that reach us as quoted strings.
TRUTHY = ("y", "yes", "true", "on", "1")
FALSY = ("n", "no", "false", "off", "0")


class TextLoader(yaml.SafeLoader):
    """Plain scalars as text, null apart: blocky's yaml.v2 keeps a string field's spelling (a
    password 0000, a client on:) where YAML 1.1 reads a number, a bool or a date. An alias is
    refused: a few of them can repeat a block of entries without end, and the importer runs as root."""

    def compose_node(self, parent, index):
        if self.check_event(yaml.AliasEvent):
            raise yaml.composer.ComposerError(None, None, "aliases are not imported; write the entries out",
                                              self.peek_event().start_mark)
        return super().compose_node(parent, index)


TextLoader.yaml_implicit_resolvers = {
    first: [(tag, pattern) for tag, pattern in resolvers if tag == "tag:yaml.org,2002:null"]
    for first, resolvers in yaml.SafeLoader.yaml_implicit_resolvers.items()
}


def load(stream):
    return yaml.load(stream, Loader=TextLoader)


# blocky takes a fractional duration, e.g. 1.5s; the model's masks want whole numbers per unit
DURATION_UNITS = (("h", 3600 * 10 ** 9), ("m", 60 * 10 ** 9), ("s", 10 ** 9), ("ms", 10 ** 6), ("us", 10 ** 3),
                  ("ns", 1))
DURATION_RE = re.compile(r"^((\d+(\.\d*)?|\.\d+)(ns|us|µs|μs|ms|s|m|h))+$", re.ASCII)


def duration_ns(text):
    """A Go duration in nanoseconds, a bare number in minutes as blocky reads it, or None."""
    if text.isascii() and text.isdigit():
        return int(text) * 60 * 10 ** 9
    if not DURATION_RE.match(text):
        return None
    total = 0
    for number, _, unit in re.findall(r"(\d+(\.\d*)?|\.\d+)(ns|us|µs|μs|ms|s|m|h)", text, re.ASCII):
        scale = dict(DURATION_UNITS)["us" if unit in ("µs", "μs") else unit]
        whole, _, fraction = number.partition(".")
        total += int(whole or 0) * scale + (int((fraction + "0" * 9)[:9]) * scale) // 10 ** 9
    return total


def whole_duration(text):
    """A Go duration rewritten with whole numbers per unit, or the text as it was."""
    if not DURATION_RE.match(text) or ("." not in text and "µ" not in text and "μ" not in text):
        return text
    total = duration_ns(text)
    parts = []
    for unit, scale in DURATION_UNITS:
        if total >= scale:
            parts.append("%d%s" % (total // scale, unit))
            total %= scale
    return "".join(parts) or "0s"


# download settings blocky applies to the sources
# files blocky may read from disk live here (and /etc/hosts for hosts files)
LIST_DIR = "/usr/local/etc/blocky/lists/"
# and a secret blocky reads from a file: value lives here
SECRET_DIR = "/usr/local/etc/blocky/secrets/"
# the one unix socket blocky may use for redis: the one the Redis plugin opens
REDIS_SOCKET = "/var/run/redis/redis.sock"


def in_directory(path, directory):
    rest = path[len(directory):] if path.startswith(directory) else ""
    return rest != "" and all(part not in ("", ".", "..") for part in rest.split("/"))


def allowed_file(source, extra=()):
    """A URL or inline entry, or a file the plugin lets blocky read; mirrors the model."""
    path = source[7:] if source.lower().startswith("file://") else source
    if path == source and (not source.startswith("/") or source.endswith("/")):
        return True
    return path in extra or in_directory(path, LIST_DIR)


def allowed_secret(value):
    """A literal secret, or a file: value naming a file in the secrets directory; mirrors the model."""
    for prefix in ("file://", "file:"):
        if value.startswith(prefix):
            return in_directory(value[len(prefix):], SECRET_DIR)
    return True


def line_break(value):
    """Fields that take one line refuse a line break."""
    return "\n" in value or "\r" in value


# the list and hosts source fields refuse these, and yaml.v2 a written one
CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f]")


def dnstap_target(value):
    """tcp:// and a host and port as Go's SplitHostPort takes them, or an allowed file: secret;
    mirrors the model, which takes no unix socket."""
    if value.startswith("file:"):
        return allowed_secret(value)
    return value.startswith("tcp://") and re.fullmatch(r"(\[[^\[\]]+\]|[^:\[\]]+):[^:\[\]]+", value[6:]) is not None


DOWNLOAD_FIELDS = (
    ("timeout", "downloadTimeout"),
    ("attempts", "downloadAttempts"),
    ("cooldown", "downloadCooldown"),
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
         "clientLookup", "caching", "queryLog", "prometheus", "pprof", "statistics", "redis",
         "log", "ports", "minTlsServeVersion", "certFile", "keyFile", "bootstrapDns",
         "hostsFile", "fqdnOnly", "filtering", "ede", "ecs", "specialUseDomains",
         "dns64", "dnssec", "http3", "rateLimit", "rebindingProtection"},
    "ports": {"dns", "http", "https", "tls", "dohPath", "freeBind", "proxyProtocol"},
    "upstreams": {"init", "timeout", "groups", "strategy", "userAgent", "quic"},
    "upstreams.init": {"strategy"},
    "upstreams.quic": {"maxIdleTimeout", "keepAlivePeriod"},
    "log": {"level", "format", "privacy", "timestamp", "target", "syslog"},
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
    "queryLog.ignore": {"sudn", "domains", "clients"},
    "redis": {"address", "username", "password", "database", "required",
              "connectionAttempts", "connectionCooldown", "sentinelUsername",
              "sentinelPassword", "sentinelAddresses"},
    "customDNS": {"customTTL", "mapping", "zone", "filterUnmappedTypes", "rewrite",
                  "fallbackUpstream"},
    "conditional": {"mapping", "rewrite", "fallbackUpstream"},
    "clientLookup": {"clients", "upstream", "singleNameOrder"},
    "filtering": {"queryTypes"},
    "prometheus": {"enable", "path", "enableClientLabel"},
    "pprof": {"enable"},
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

# duration fields whose mask takes a bare 0 (off), as the other masks do not
BARE_ZERO_FIELDS = {"general.refreshPeriod", "general.downloadReadTimeout", "general.cacheMinTime",
                    "general.cacheMaxTime", "general.customTTL", "hostsFile.hostsTTL"}
# blocky only checks the sign of these, so any negative duration means the same as -1
NEGATIVE_FIELDS = {"general.cacheMinTime", "general.cacheMaxTime", "general.cacheTimeNegative",
                   "general.downloadReadHeaderTimeout"}
SCHEDULE_KEYS = {"start", "end", "weekdays"}
BOOTSTRAP_KEYS = {"upstream", "ips", "resolvFile"}

# valid blocky keys with no equivalent in the plugin
UNSUPPORTED = {
    "ports.freeBind": "Linux-only, not applicable on FreeBSD.",
    "log.timestamp": "handled by syslog on OPNsense; blocky's own timestamp is always disabled.",
    "log.target": "Blocky always logs to syslog on OPNsense.",
    "log.syslog": "Blocky always logs to syslog on OPNsense.",
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

# blocky's defaults for the keys a deprecated one moves to; the others default to empty
MOVE_DEFAULTS = {
    "upstreams.timeout": "2s", "upstreams.init.strategy": "blocking", "ports.dns": "53",
    "log.level": "info", "log.format": "text", "log.privacy": "false",
    "blocking.loading.downloads.timeout": "5s", "blocking.loading.downloads.attempts": "3",
    "blocking.loading.downloads.cooldown": "500ms", "blocking.loading.refreshPeriod": "4h",
    "blocking.loading.concurrency": "4", "blocking.loading.strategy": "blocking",
    "blocking.loading.maxErrorsPerSource": "5", "hostsFile.loading.refreshPeriod": "4h",
}


def at_default(key, value):
    """Whether blocky takes this value of a key as the key's default, as its migrations check; an
    explicit {} or [] differs from an absent one there."""
    if value is None or value == "":
        return True
    if value in ([], {}):
        return False
    if key == "ports.dns" and isinstance(value, (list, str, int)) and not isinstance(value, bool):
        # blocky reads a list or comma separated ports, and puts a colon before a bare port
        ports = [str(port) for port in value] if isinstance(value, list) else str(value).split(",")
        return [port if ":" in port else ":" + port for port in ports] == [":53"]
    default = MOVE_DEFAULTS.get(key)
    if default is None or isinstance(value, (list, dict)):
        return False
    text = str(value).strip().lower()
    if default == "false":
        return text in FALSY
    if not (default.isascii() and default.isdigit()) and duration_ns(default) is not None:
        return duration_ns(text) == duration_ns(default)
    return text == default


class Mapper:
    def __init__(self, doc):
        self.doc = doc if isinstance(doc, dict) else {}
        self.scalars = {}
        self.arrays = {}
        self.seen = set()
        self.skipped = []
        self.warnings = []
        # keys found empty, each warned about once
        self.emptied: set = set()

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

    def _zone_text(self, value, label):
        """Zone text: a leading blank means "same owner as before", so only blank lines and
        trailing space go."""
        text = self._scalar(value, label)
        return None if text is None else str(value).rstrip().lstrip("\r\n")

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

    def _client_key(self, value, label):
        """PyYAML's YAML 1.1 resolver reads an unquoted 11:22:33:44:55:59 as an integer;
        quoting it in config.yml keeps it a MAC address."""
        if isinstance(value, int) and not isinstance(value, bool):
            self.warnings.append("%s: %s looks like an unquoted MAC address; quote it in "
                                 "config.yml to import it." % (label, value))
            return None
        return str(value)

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
        if not value:
            return  # the import starts from the defaults
        if "%s.%s" % (section, field) in DURATION_FIELDS and value[:1] in ("+", "-"):
            # Go reads +d as d and -0 as 0; blocky only checks the sign of a NEGATIVE_FIELDS one
            if value[0] == "+" or duration_ns(value[1:]) == 0:
                value = value[1:]
            elif "%s.%s" % (section, field) in NEGATIVE_FIELDS:
                self.scalars.setdefault(section, {})[field] = "-1"
                return
        if "%s.%s" % (section, field) in DURATION_FIELDS:
            if value == "0" and "%s.%s" % (section, field) in BARE_ZERO_FIELDS:
                pass  # the field's own spelling for off
            elif value.isascii() and value.isdigit():
                self.warnings.append("%s: %s has no unit; imported as %sm, the way blocky reads it."
                                     % (label, value, value))
                value += "m"
            else:
                value = whole_duration(value)
        self.scalars.setdefault(section, {})[field] = value

    def _empty(self, parts):
        """The key on this path that is present but empty, if any: a null section or value, or an
        empty text or list, which blocky reads as its zero value rather than its default."""
        node = self.doc
        for depth, key in enumerate(parts):
            if not isinstance(node, dict) or key not in node:
                return None
            node = node[key]
            if node is None or (depth == len(parts) - 1 and node in ("", [])):
                return ".".join(parts[:depth + 1])
        return None

    def _map(self, path, section, field, transform=None):
        parts = path.split(".")
        empty = self._empty(parts)
        if empty is None:
            self._put(section, field, self._get(*parts), path, transform)
        elif transform == self._bool:
            self.scalars.setdefault(section, {})[field] = "0"
            self.warnings.append("%s: empty, which blocky reads as off; imported as off." % path)
        elif empty not in self.emptied:
            self.emptied.add(empty)
            self.warnings.append("%s: empty, which blocky reads as zero or nothing; the default was kept." % empty)

    def _row(self, name, row, label):
        key = (name, tuple(sorted(row.items())))
        if key in self.seen:
            self.warnings.append("%s: duplicate entry; imported once." % label)
            return
        self.seen.add(key)
        self.arrays.setdefault(name, []).append(row)

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
        """Move deprecated keys as blocky does."""
        # blocky applies it before blocking.startStrategy, which then counts the strategy as set
        fail_start = self._pop("blocking.failStartOnListError")
        if fail_start is not None and self._bool(fail_start, "blocking.failStartOnListError") == "1":
            self._migrate_set("blocking.failStartOnListError", "blocking.loading.strategy",
                              "failOnError")
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
        file_path = self._pop("hostsFile.filePath")
        if file_path is not None:
            self._migrate_set("hostsFile.filePath", "hostsFile.sources", [file_path])

    def _migrate_set(self, old, new, value):
        """blocky takes the deprecated value unless the new key holds something other than its default."""
        parts = new.split(".")
        if not at_default(new, self._get(*parts)):
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

    def _tls_version(self, value, label):
        """blocky serves TLS 1.2 at least, and raises an older setting itself."""
        text = self._scalar(value, label)
        if text in ("1.0", "1.1"):
            self.warnings.append("%s: blocky serves TLS 1.2 at least; imported as 1.2." % label)
            return "1.2"
        return text

    def _general_connect_tls(self):
        self._map("connectIPVersion", "general", "connectIPVersion")
        self._map("minTlsServeVersion", "general", "minTlsServeVersion", self._tls_version)
        for key in ("certFile", "keyFile"):
            if self._get(key) is not None:
                self.warnings.append("%s: import the certificate under System: Trust and select it "
                                     "in the settings; not imported." % key)
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
                if path and not in_directory(path.replace("\r", ""), LIST_DIR):
                    self.warnings.append("bootstrapDns.resolvFile: %s is outside %s; not imported."
                                         % (path, LIST_DIR.rstrip("/")))
                    path = None
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

    def _sources(self, value, label, extra=()):
        """A list or hosts source as blocky reads it, in the form the settings read the same way: text
        with a line break is inline entries, one per line, a tab as the space blocky reads it as; a
        line starting with http is a download; anything else is a file, which only the list directory
        (and extra) may hold."""
        if isinstance(value, (dict, list, tuple)) or isinstance(value, bool) or value is None:
            self._scalar(value, label)  # says why
            return []
        text = str(value)
        if "\n" in text:
            out = []
            for line in text.splitlines():
                line = line.strip().replace("\t", " ")
                if not line or line.startswith("#"):
                    continue
                if CONTROL.search(line):
                    self.warnings.append("%s: %r has control characters; not imported." % (label, line))
                    continue
                if line.startswith(("http://", "https://", "file://")) or (line.startswith("/") and not line.endswith("/")):
                    # a single entry like this would be a download or a file to the settings
                    self.warnings.append("%s: %s is a line of inline text to blocky, which matches no "
                                         "name; not imported." % (label, line))
                    continue
                out.append(line)
            return out
        text = text.strip()
        if text.startswith("http") and not text.startswith(("http://", "https://")):
            self.warnings.append("%s: blocky would download %s, which is no URL; not imported." % (label, text))
            return []
        path = text[len("file://"):] if text.startswith("file://") else text
        if not text.startswith("http") and (not path.startswith("/") or path.endswith("/")):
            self.warnings.append("%s: blocky reads %s as a file, which needs a full path to a file "
                                 "here; not imported." % (label, text))
            return []
        if CONTROL.search(text):
            self.warnings.append("%s: %r has control characters; not imported." % (label, text))
            return []
        if not allowed_file(text, extra):
            self.warnings.append("%s: %s is a file outside %s; not imported." % (label, text, LIST_DIR.rstrip("/")))
            return []
        return [text]

    def _blocking(self):
        for yml_key, name in (("denylists", "denylists"), ("allowlists", "allowlists")):
            for group, sources in self._mapping("blocking.%s" % yml_key).items():
                label = "blocking.%s.%s" % (yml_key, group)
                for source in self._sequence(sources, label):
                    for one in self._sources(source, label):
                        self._row(name, {
                            "enabled": "1", "group": str(group), "source": one,
                        }, "%s: %s" % (label, one))
        for client, groups in self._mapping("blocking.clientGroupsBlock").items():
            label = "blocking.clientGroupsBlock.%s" % client
            value = self._list(groups, label)
            name = self._client_key(client, label)
            if value is None or name is None:
                continue
            kept = self._listed(value.split(","), label)
            if not kept:
                self.warnings.append("%s: none of its groups has a list; not imported%s." % (
                    label, "" if name == "default" else ", so the default groups apply to this client"))
                continue
            self._row("clientgroups", {
                "enabled": "1", "client": name, "groups": ",".join(kept),
            }, label)
        self._map("blocking.blockType", "general", "blockType", self._list)
        self._map("blocking.blockTTL", "general", "blockTTL")
        self._map("blocking.loading.refreshPeriod", "general", "refreshPeriod")
        self._map("blocking.loading.strategy", "general", "loadingStrategy")
        self._map("blocking.loading.maxErrorsPerSource", "general", "maxErrorsPerSource")
        self._map("blocking.loading.concurrency", "general", "loadingConcurrency")
        for yml_key, field in DOWNLOAD_FIELDS + SERVER_TIMEOUT_FIELDS:
            self._map("blocking.loading.downloads.%s" % yml_key, "general", field)
        self._download_cache("blocking.loading.downloads.cachePath", "general", "/var/cache/blocky/lists")
        self._schedules()

    def _listed(self, groups, label):
        """The groups that have a list: blocky only warns about one without, whose blocking never
        applies, and the settings refuse it."""
        listed = {row["group"].strip() for name in ("denylists", "allowlists") for row in self.arrays.get(name, [])}
        kept = []
        for group in groups:
            if group.strip() in listed:
                kept.append(group)
            elif group.strip():
                self.warnings.append("%s: group %s has no list; the reference was not imported." % (label, group))
        return kept

    def _schedules(self):
        schedules = self._mapping("blocking.schedules")
        # invert group -> [schedule names] into schedule name -> [groups]
        sched_groups: dict = {}
        for group, names in self._mapping("blocking.listSchedules").items():
            label = "blocking.listSchedules.%s" % group
            if not self._listed([str(group)], label):
                continue
            for name in self._sequence(names, label):
                if str(name) not in schedules:
                    self.warnings.append("%s: there is no schedule named %s; the reference "
                                         "was not imported." % (label, name))
                    continue
                sched_groups.setdefault(str(name), []).append(str(group))
        parsed = {}
        for name, spec in schedules.items():
            label = "blocking.schedules.%s" % name
            spec = self._as_mapping(spec, label)
            for key in sorted(set(spec) - SCHEDULE_KEYS):
                self.warnings.append("%s.%s: not recognized; not imported." % (label, key))
            weekdays = (self._list(spec.get("weekdays"), "%s.weekdays" % label) or "").lower()
            if weekdays == "":
                # blocky only warns about a schedule without weekdays, which never applies
                self.warnings.append("%s: no weekdays; not imported." % label)
                continue
            if not sched_groups.get(str(name)):
                # the model needs a group, blocky allows an unused schedule
                self.warnings.append("%s: no list group uses this schedule; not imported." % label)
                continue
            start = self._timeofday(spec.get("start"), "%s.start" % label) or ""
            end = self._timeofday(spec.get("end"), "%s.end" % label) or ""
            if (start == "") != (end == ""):
                # blocky only warns about one without the other; the settings take both or neither
                self.warnings.append("%s: a schedule needs both start and end, or neither; "
                                     "imported as all day." % label)
                start = end = ""
            parsed[str(name)] = (label, weekdays, start, end)
        # blocky never opens a window that ends where it starts, which the settings refuse: a group
        # with another schedule only loses it, as in blocky; one without gets it as all day
        never = {name for name, (_, _, start, end) in parsed.items() if start != "" and start == end}
        opens = {group for name in parsed if name not in never for group in sched_groups[name]}
        for name, (label, weekdays, start, end) in parsed.items():
            groups = sched_groups[name]
            if name in never:
                covered = [group for group in groups if group in opens]
                groups = [group for group in groups if group not in opens]
                if covered:
                    self.warnings.append("%s: blocky never applies a schedule that ends where it starts, so %s "
                                         "keeps only its other schedules." % (label, ", ".join(covered)))
                if not groups:
                    continue
                self.warnings.append("%s: blocky never applies a schedule that ends where it starts; imported "
                                     "as all day for %s." % (label, ", ".join(groups)))
                start = end = ""
            self._row("schedules", {
                "enabled": "1",
                "name": name,
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
            client = self._client_key(name, label)
            if value is not None and client is not None:
                self._row("clientlookupclients", {
                    "enabled": "1", "name": client, "ips": value,
                }, label)

    def _log_level(self, value, label):
        """A logrus level in any case and spelling; the model offers error to trace."""
        text = self._scalar(value, label)
        if text is None:
            return None
        level = {"warning": "warn", "panic": "error", "fatal": "error"}.get(text.lower(), text.lower())
        if level != text:
            self.warnings.append("%s: %s imported as %s." % (label, text, level))
        return level

    def _prometheus_log(self):
        self._map("prometheus.enable", "general", "prometheus", self._bool)
        self._map("prometheus.path", "general", "prometheusPath")
        self._map("prometheus.enableClientLabel", "general", "prometheusClientLabel", self._bool)
        self._map("pprof.enable", "general", "pprof", self._bool)
        self._map("log.level", "general", "logLevel", self._log_level)
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
        self._rewrites("customDNS.rewrite", "customdnsrewrite")
        zone = self._zone_text(self._get("customDNS", "zone"), "customDNS.zone")
        if zone:
            self._put("general", "customZone", zone, "customDNS.zone", lambda value, label: value)

    def _conditional(self):
        self._map("conditional.fallbackUpstream", "general", "conditionalFallback", self._bool)
        for domain, resolver in self._mapping("conditional.mapping").items():
            label = "conditional.mapping.%s" % domain
            value = self._list(resolver, label)
            if value is not None:
                self._row("conditional", {
                    "enabled": "1", "domain": str(domain), "resolver": value,
                }, label)
        self._rewrites("conditional.rewrite", "conditionalrewrite")

    def _rewrites(self, path, name):
        """Rewrite keys as the settings match them, lowercase and without a trailing dot: blocky
        keeps one of the keys that differ only in case, and the first of them is imported. Blocky
        never matches a key with a trailing dot, so one without it is imported first."""
        first: dict = {}
        for src, dst in sorted(self._mapping(path).items(), key=lambda item: str(item[0]).strip().endswith(".")):
            label = "%s.%s" % (path, src)
            value = self._scalar(dst, label)
            if not value:
                continue
            # the settings also trim the key
            key = str(src).strip().lower().rstrip(".")
            if key in first:
                self.warnings.append("%s: the same domain as %s, which is imported instead." % (label, first[key]))
                continue
            first[key] = src
            self._row(name, {
                "enabled": "1", "fromDomain": str(src).strip(), "toDomain": value,
            }, label)

    def _query_log(self):
        for field in ("type", "logRetentionDays", "creationAttempts", "creationCooldown", "flushInterval"):
            self._map("queryLog.%s" % field, "queryLog", field)
        if self._get("queryLog", "type") is None:
            # blocky logs to the console when no type is set
            self.scalars.setdefault("queryLog", {})["type"] = "console"
            self.warnings.append("queryLog.type: not set, which blocky reads as Console, logging every query; "
                                 "imported as Console.")
        fixed = {"csv": "/var/db/blocky/querylog", "csv-client": "/var/db/blocky/querylog",
                 "sqlite": "/var/db/blocky/querylog.db"}.get(str(self._get("queryLog", "type") or "").strip())
        target = self._get("queryLog", "target")
        if fixed is None and self._get("queryLog", "type") == "dnstap" and isinstance(target, str) \
                and (line_break(target) or not dnstap_target(target)):
            # a unix socket would be connected to as root, so the log is left off
            self.warnings.append("queryLog.target: only tcp://host:port is taken for dnstap; query logging "
                                 "was left off.")
            self.scalars["queryLog"]["type"] = "none"
        elif fixed is None and isinstance(target, str) and (line_break(target) or not allowed_secret(target)):
            why = "line breaks are not taken" if line_break(target) else \
                "a file: value must name a file in %s" % SECRET_DIR.rstrip("/")
            if self._get("queryLog", "type") in ("mysql", "postgresql", "timescale"):
                # these need a target, so the log is left off
                self.warnings.append("queryLog.target: %s; query logging was left off." % why)
                self.scalars["queryLog"]["type"] = "none"
            else:
                self.warnings.append("queryLog.target: %s; not imported." % why)
        elif fixed is None:
            self._map("queryLog.target", "queryLog", "target")
        elif target is not None:
            self.warnings.append("queryLog.target: this log type is written to %s; not imported." % fixed)
        self._map("queryLog.fields", "queryLog", "fields", self._list)
        self._map("queryLog.ignore.sudn", "queryLog", "ignoreSudn", self._bool)
        self._map("queryLog.ignore.domains", "queryLog", "ignoreDomains", self._list)
        self._map("queryLog.ignore.clients", "queryLog", "ignoreClients", self._list)

    def _redis(self):
        address = self._get("redis", "address")
        if isinstance(address, str) and line_break(address):
            self.warnings.append("redis.address: line breaks are not taken; not imported.")
        elif isinstance(address, str) and address.startswith("/") and address != REDIS_SOCKET:
            self.warnings.append("redis.address: only the Redis plugin socket %s is taken; not imported."
                                 % REDIS_SOCKET)
        else:
            self._map("redis.address", "redis", "address")
        for field in ("username", "database", "connectionAttempts", "connectionCooldown", "sentinelUsername"):
            self._map("redis.%s" % field, "redis", field)
        for field in ("password", "sentinelPassword"):
            value = self._get("redis", field)
            if isinstance(value, str) and line_break(value):
                self.warnings.append("redis.%s: line breaks are not taken; not imported." % field)
            elif isinstance(value, str) and not allowed_secret(value):
                self.warnings.append("redis.%s: a file: value must name a file in %s; not imported."
                                     % (field, SECRET_DIR.rstrip("/")))
            else:
                self._map("redis.%s" % field, "redis", field)
        if "address" in self.scalars.get("redis", {}):
            self._map("redis.required", "redis", "required", self._bool)
        self._map("redis.sentinelAddresses", "redis", "sentinelAddresses", self._list)
        sentinels = self.scalars.get("redis", {}).get("sentinelAddresses")
        if sentinels:
            kept = [one for one in sentinels.split(",") if not one.strip().startswith("/")]
            if len(kept) < len(sentinels.split(",")):
                self.warnings.append("redis.sentinelAddresses: unix sockets would be connected to as root; "
                                     "not imported.")
            if kept:
                self.scalars["redis"]["sentinelAddresses"] = ",".join(kept)
            else:
                del self.scalars["redis"]["sentinelAddresses"]

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
        entries: list = []
        for source in self._sequence(self._get("hostsFile", "sources"), "hostsFile.sources"):
            entries += self._sources(source, "hostsFile.sources", ("/etc/hosts",))
        self._put("hostsFile", "sources", entries, "hostsFile.sources", self._list)
        self._map("hostsFile.hostsTTL", "hostsFile", "hostsTTL")
        self._map("hostsFile.filterLoopback", "hostsFile", "filterLoopback", self._bool)
        self._map("hostsFile.loading.refreshPeriod", "hostsFile", "refreshPeriod")
        self._map("hostsFile.loading.strategy", "hostsFile", "loadingStrategy")
        self._map("hostsFile.loading.maxErrorsPerSource", "hostsFile", "maxErrorsPerSource")
        self._map("hostsFile.loading.concurrency", "hostsFile", "concurrency")
        for yml_key, field in DOWNLOAD_FIELDS:
            self._map("hostsFile.loading.downloads.%s" % yml_key, "hostsFile", field)
        self._download_cache("hostsFile.loading.downloads.cachePath", "hostsFile", "/var/cache/blocky/hosts")

    def _download_cache(self, path, section, directory):
        """The plugin keeps each download cache in a fixed directory, so a path turns it on."""
        value = self._scalar(self._get(*path.split(".")), path)
        if not value:
            return
        self.scalars.setdefault(section, {})["downloadCache"] = "1"
        if value.rstrip("/") != directory:
            self.warnings.append("%s: the cache is kept in %s; caching turned on." % (path, directory))

    def _ecs(self):
        self._map("ecs.useAsClient", "ecs", "useAsClient", self._bool)
        self._map("ecs.forward", "ecs", "forward", self._bool)
        self._map("ecs.ipv4Mask", "ecs", "ipv4Mask")
        self._map("ecs.ipv6Mask", "ecs", "ipv6Mask")

    def _dnssec_limit(self, value, label):
        """blocky reads a limit of 0 as its default, which is what the field is left at."""
        text = self._scalar(value, label)
        if text == "0":
            self.warnings.append("%s: 0 means blocky's default; imported as that." % label)
            return None
        return text

    def _dnssec(self):
        self._map("dnssec.validate", "dnssec", "validate", self._bool)
        self._map("dnssec.clockSkewToleranceSec", "dnssec", "clockSkewToleranceSec")
        for field in ("maxChainDepth", "cacheExpirationHours", "maxNSEC3Iterations", "maxUpstreamQueries"):
            self._map("dnssec.%s" % field, "dnssec", field, self._dnssec_limit)
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
    name = os.path.basename(sys.argv[1])
    if not name.startswith(TEMP_PREFIX):
        print(json.dumps({"error": "the file was not handed over by the web interface."}))
        sys.exit(0)
    try:
        # no links, and a FIFO is refused rather than waited on
        with open(os.open(os.path.join(TEMP_DIR, name), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as handle:
            info = os.fstat(handle.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise OSError("not a file the web interface wrote")
            data = handle.read(IMPORT_MAX + 1)
        if len(data) > IMPORT_MAX:
            print(json.dumps({"error": "the file is larger than a configuration should be."}))
            sys.exit(0)
        doc = load(data.decode("utf-8"))
    except UnicodeDecodeError:
        print(json.dumps({"error": "the file is not valid UTF-8 text."}))
        sys.exit(0)
    except OSError as exc:
        print(json.dumps({"error": "could not read the file: %s" % (exc.strerror or exc)}))
        sys.exit(0)
    except (yaml.YAMLError, ValueError, RecursionError) as exc:
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
