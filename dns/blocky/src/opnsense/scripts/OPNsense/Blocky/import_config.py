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

Read a Blocky config.yml into the settings: each value as the file gives it, in the field
templates/OPNsense/Blocky/config.yml writes it from. Emits JSON on stdout:

  {
    "scalars":  { "general": {...}, "dnssec": {...}, ... },
    "arrays":   { "upstreams": [ {...}, ... ], ... },
    "labels":   { "scalars": { "<section>.<field>": "<key>" }, "arrays": { "upstreams": [ "<key>", ... ] } },
    "skipped":  [ "<key>", ... ],
    "warnings": [ "<message>", ... ]
  }

The settings check the values (Blocky::applyImport()) and leave out what they refuse, naming the
key from "labels". "skipped" lists the keys the settings have no field for.
"""

import json
import os
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

# true and false as Blocky's yaml.v2 reads them (YAML 1.1)
TRUTHY = ("y", "yes", "true", "on")
FALSY = ("n", "no", "false", "off")

# config.yml key -> settings field
FIELDS = {
    "upstreams.strategy": "general.strategy",
    "upstreams.timeout": "general.timeout",
    "upstreams.init.strategy": "general.initStrategy",
    "upstreams.userAgent": "general.userAgent",
    "upstreams.quic.maxIdleTimeout": "general.quicMaxIdleTimeout",
    "upstreams.quic.keepAlivePeriod": "general.quicKeepAlivePeriod",
    "connectIPVersion": "general.connectIPVersion",
    "customDNS.customTTL": "general.customTTL",
    "customDNS.filterUnmappedTypes": "general.filterUnmappedTypes",
    "customDNS.zone": "general.customZone",
    "conditional.fallbackUpstream": "general.conditionalFallback",
    "blocking.blockType": "general.blockType",
    "blocking.blockTTL": "general.blockTTL",
    "blocking.loading.strategy": "general.loadingStrategy",
    "blocking.loading.maxErrorsPerSource": "general.maxErrorsPerSource",
    "blocking.loading.concurrency": "general.loadingConcurrency",
    "blocking.loading.refreshPeriod": "general.refreshPeriod",
    "blocking.loading.downloads.timeout": "general.downloadTimeout",
    "blocking.loading.downloads.writeTimeout": "general.downloadWriteTimeout",
    "blocking.loading.downloads.readTimeout": "general.downloadReadTimeout",
    "blocking.loading.downloads.readHeaderTimeout": "general.downloadReadHeaderTimeout",
    "blocking.loading.downloads.attempts": "general.downloadAttempts",
    "blocking.loading.downloads.cooldown": "general.downloadCooldown",
    "caching.minTime": "general.cacheMinTime",
    "caching.maxTime": "general.cacheMaxTime",
    "caching.cacheTimeNegative": "general.cacheTimeNegative",
    "caching.maxItemsCount": "general.maxItemsCount",
    "caching.prefetching": "general.prefetching",
    "caching.prefetchExpires": "general.prefetchExpires",
    "caching.prefetchThreshold": "general.prefetchThreshold",
    "caching.prefetchMaxItemsCount": "general.prefetchMaxItemsCount",
    "caching.exclude": "general.cacheExclude",
    "clientLookup.upstream": "general.clientLookupUpstream",
    "clientLookup.singleNameOrder": "general.clientLookupOrder",
    "prometheus.enable": "general.prometheus",
    "prometheus.path": "general.prometheusPath",
    "prometheus.enableClientLabel": "general.prometheusClientLabel",
    "pprof.enable": "general.pprof",
    "statistics.enable": "statistics.enable",
    "queryLog.type": "queryLog.type",
    "queryLog.target": "queryLog.target",
    "queryLog.logRetentionDays": "queryLog.logRetentionDays",
    "queryLog.creationAttempts": "queryLog.creationAttempts",
    "queryLog.creationCooldown": "queryLog.creationCooldown",
    "queryLog.flushInterval": "queryLog.flushInterval",
    "queryLog.fields": "queryLog.fields",
    "queryLog.ignore.sudn": "queryLog.ignoreSudn",
    "queryLog.ignore.domains": "queryLog.ignoreDomains",
    "queryLog.ignore.clients": "queryLog.ignoreClients",
    "redis.address": "redis.address",
    "redis.username": "redis.username",
    "redis.password": "redis.password",
    "redis.database": "redis.database",
    "redis.required": "redis.required",
    "redis.connectionAttempts": "redis.connectionAttempts",
    "redis.connectionCooldown": "redis.connectionCooldown",
    "redis.sentinelUsername": "redis.sentinelUsername",
    "redis.sentinelPassword": "redis.sentinelPassword",
    "redis.sentinelAddresses": "redis.sentinelAddresses",
    "minTlsServeVersion": "general.minTlsServeVersion",
    "filtering.queryTypes": "filtering.queryTypes",
    "rebindingProtection.enable": "rebindingProtection.enable",
    "rebindingProtection.allowedDomains": "rebindingProtection.allowedDomains",
    "rateLimit.enable": "rateLimit.enable",
    "rateLimit.rate": "rateLimit.rate",
    "rateLimit.burst": "rateLimit.burst",
    "rateLimit.ipv4Prefix": "rateLimit.ipv4Prefix",
    "rateLimit.ipv6Prefix": "rateLimit.ipv6Prefix",
    "rateLimit.allowlist": "rateLimit.allowlist",
    "fqdnOnly.enable": "fqdnOnly.enable",
    "hostsFile.sources": "hostsFile.sources",
    "hostsFile.hostsTTL": "hostsFile.hostsTTL",
    "hostsFile.filterLoopback": "hostsFile.filterLoopback",
    "hostsFile.loading.strategy": "hostsFile.loadingStrategy",
    "hostsFile.loading.maxErrorsPerSource": "hostsFile.maxErrorsPerSource",
    "hostsFile.loading.concurrency": "hostsFile.concurrency",
    "hostsFile.loading.refreshPeriod": "hostsFile.refreshPeriod",
    "hostsFile.loading.downloads.timeout": "hostsFile.downloadTimeout",
    "hostsFile.loading.downloads.attempts": "hostsFile.downloadAttempts",
    "hostsFile.loading.downloads.cooldown": "hostsFile.downloadCooldown",
    "ports.dns": "general.dnsPort",
    "ports.http": "general.httpPort",
    "ports.tls": "general.tlsPort",
    "ports.https": "general.httpsPort",
    "ports.dohPath": "general.dohPath",
    "ports.proxyProtocol": "general.proxyProtocol",
    "http3.enable": "general.http3",
    "log.level": "general.logLevel",
    "log.format": "general.logFormat",
    "log.privacy": "general.logPrivacy",
    "ede.enable": "ede.enable",
    "specialUseDomains.enable": "specialUseDomains.enable",
    "specialUseDomains.rfc6762-appendixG": "specialUseDomains.rfc6762",
    "ecs.useAsClient": "ecs.useAsClient",
    "ecs.forward": "ecs.forward",
    "ecs.ipv4Mask": "ecs.ipv4Mask",
    "ecs.ipv6Mask": "ecs.ipv6Mask",
    "dnssec.validate": "dnssec.validate",
    "dnssec.maxChainDepth": "dnssec.maxChainDepth",
    "dnssec.cacheExpirationHours": "dnssec.cacheExpirationHours",
    "dnssec.maxUpstreamQueries": "dnssec.maxUpstreamQueries",
    "dnssec.maxNSEC3Iterations": "dnssec.maxNSEC3Iterations",
    "dnssec.clockSkewToleranceSec": "dnssec.clockSkewToleranceSec",
    "dnssec.trustAnchors": "dnssec.trustAnchors",
    "dns64.enable": "dns64.enable",
    "dns64.prefixes": "dns64.prefix",
    "dns64.exclusionSet": "dns64.exclusionSet",
}
# the fields that take 1 or 0
BOOLEANS = {
    "general.filterUnmappedTypes", "general.conditionalFallback", "general.prefetching", "general.prometheus",
    "general.prometheusClientLabel", "general.pprof", "general.http3", "general.logPrivacy", "statistics.enable",
    "queryLog.ignoreSudn", "redis.required", "rebindingProtection.enable", "rateLimit.enable", "fqdnOnly.enable",
    "hostsFile.filterLoopback", "ede.enable", "specialUseDomains.enable", "specialUseDomains.rfc6762",
    "ecs.useAsClient", "ecs.forward", "dnssec.validate", "dns64.enable",
}
# config.yml mapping of lists -> a row per entry: grid section, key field, entry field
ENTRIES = {
    "upstreams.groups": ("upstreams", "group", "server"),
    "blocking.denylists": ("denylists", "group", "source"),
    "blocking.allowlists": ("allowlists", "group", "source"),
}
# config.yml mapping -> a row per key: grid section, key field, value field
MAPS = {
    "blocking.clientGroupsBlock": ("clientgroups", "client", "groups"),
    "customDNS.mapping": ("customdns", "domain", "ip"),
    "customDNS.rewrite": ("customdnsrewrite", "fromDomain", "toDomain"),
    "conditional.mapping": ("conditional", "domain", "resolver"),
    "conditional.rewrite": ("conditionalrewrite", "fromDomain", "toDomain"),
    "clientLookup.clients": ("clientlookupclients", "name", "ips"),
}


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


def text(value):
    """A value as the file gives it, a list as the settings' comma list; None for a mapping."""
    if isinstance(value, dict):
        return None
    if isinstance(value, list):
        items = [text(item) for item in value]
        return None if None in items else ",".join(items)
    return "" if value is None else str(value).strip()


class Mapper:
    def __init__(self, doc):
        self.doc = doc if isinstance(doc, dict) else {}
        self.scalars: dict = {}
        self.arrays: dict = {}
        self.labels: dict = {"scalars": {}, "arrays": {}}
        self.used: set = set()
        self.warnings: list = []

    def get(self, path):
        node = self.doc
        for key in path.split("."):
            if not isinstance(node, dict) or key not in node:
                return None
            node = node[key]
        self.used.add(path)
        return node

    def mapping(self, path):
        node = self.get(path)
        if node is not None and not isinstance(node, dict):
            self.warnings.append("%s: expected a mapping; not imported." % path)
        return node.items() if isinstance(node, dict) else []

    def row(self, name, row, label):
        self.arrays.setdefault(name, []).append(dict(row, enabled="1"))
        self.labels["arrays"].setdefault(name, []).append(label)

    @staticmethod
    def is_path(value):
        """What the settings read as a download or a file, as the template writes it."""
        return value.startswith(("http://", "https://", "file://")) or (value.startswith("/") and not value.endswith("/"))

    def sources(self, value, label):
        """A list or hosts source as Blocky reads it: text with a line break is one entry per line,
        and one line is a download or a file, which the settings take only by its full path."""
        if "\n" in value:
            lines = [line.strip() for line in value.splitlines() if line.strip() and not line.strip().startswith("#")]
            for line in [line for line in lines if self.is_path(line)]:
                # one entry like this would be a download or a file to the settings
                self.warnings.append("%s: %s is a line of inline text to blocky, which matches no name; not imported."
                                     % (label, line))
            return [line for line in lines if not self.is_path(line)]
        value = value.strip()
        if self.is_path(value):
            return [value]
        self.warnings.append("%s: blocky reads %s as a file, which needs a full path here; not imported." % (label, value))
        return []

    def run(self):
        for path, ref in FIELDS.items():
            value = self.get(path)
            if value is None:
                continue
            if path == "hostsFile.sources":
                value = [entry for item in (value if isinstance(value, list) else [value])
                         for entry in self.sources(str(item), path)]
            value = text(value)
            if value is None:
                self.warnings.append("%s: expected a value or a list; not imported." % path)
                continue
            if ref in BOOLEANS and value.lower() in TRUTHY + FALSY:
                value = "1" if value.lower() in TRUTHY else "0"
            section, field = ref.split(".")
            self.scalars.setdefault(section, {})[field] = value
            self.labels["scalars"][ref] = path
        for path, (name, key_field, entry_field) in ENTRIES.items():
            for key, entries in self.mapping(path):
                label = "%s.%s" % (path, key)
                for item in entries if isinstance(entries, list) else [entries]:
                    found = self.sources("" if item is None else str(item), label) if entry_field == "source" \
                        else [text(item) or ""]
                    for entry in found:
                        self.row(name, {key_field: str(key), entry_field: entry}, "%s: %s" % (label, entry))
        for path, (name, key_field, value_field) in MAPS.items():
            for key, value in self.mapping(path):
                self.row(name, {key_field: str(key), value_field: text(value) or ""}, "%s.%s" % (path, key))
        self._bootstrap()
        self._schedules()
        return {
            "scalars": self.scalars,
            "arrays": self.arrays,
            "labels": self.labels,
            "skipped": self._unused(self.doc, ""),
            "warnings": self.warnings,
        }

    def _bootstrap(self):
        entries = self.get("bootstrapDns")
        for entry in entries if isinstance(entries, list) else [] if entries is None else [entries]:
            if not isinstance(entry, dict):
                entry = {"upstream": entry}
            if entry.get("resolvFile") is not None:
                path = text(entry["resolvFile"]) or ""
                self.row("bootstrap", {"type": "resolvfile", "content": path}, "bootstrapDns: %s" % path)
            if entry.get("upstream") is not None:
                upstream = text(entry["upstream"]) or ""
                self.row("bootstrap", {"type": "resolver", "content": upstream, "ips": text(entry.get("ips")) or ""},
                         "bootstrapDns: %s" % upstream)

    def _schedules(self):
        groups: dict = {}
        for group, names in self.mapping("blocking.listSchedules"):
            for name in names if isinstance(names, list) else [names]:
                groups.setdefault(str(name), []).append(str(group))
        for name, spec in self.mapping("blocking.schedules"):
            spec = spec if isinstance(spec, dict) else {}
            self.row("schedules", {"name": str(name), "groups": ",".join(groups.get(str(name), [])),
                                   "weekdays": text(spec.get("weekdays")) or "", "start": text(spec.get("start")) or "",
                                   "end": text(spec.get("end")) or ""}, "blocking.schedules.%s" % name)

    def _unused(self, node, path):
        """The keys under path that nothing read."""
        found = []
        for key, value in node.items():
            full = "%s.%s" % (path, key) if path else str(key)
            if full in self.used:
                continue
            if isinstance(value, dict) and any(used.startswith(full + ".") for used in self.used):
                found += self._unused(value, full)
            else:
                found.append(full)
        return found


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
