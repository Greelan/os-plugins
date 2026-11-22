"""config.yml as OPNsense renders it: valid YAML, free text kept as values, fixed paths."""

import copy
import os
import sys
import unittest
import xml.etree.ElementTree as ET

import jinja2

PLUGIN = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src", "opnsense")
TEMPLATES = os.path.join(PLUGIN, "service", "templates")
sys.path.insert(0, os.path.join(PLUGIN, "scripts", "OPNsense", "Blocky", "lib"))

import yaml  # noqa: E402  (the vendored PyYAML)


def model_defaults(node):
    """The model's settings with their defaults, as the template sees a fresh config."""
    result = {}
    for child in node:
        kind = child.get("type")
        if kind == "ArrayField":
            result[child.tag] = []
        elif kind:
            result[child.tag] = child.findtext("Default") or ""
        elif len(child):
            result[child.tag] = model_defaults(child)
    return result


DEFAULTS = model_defaults(ET.parse(os.path.join(PLUGIN, "mvc", "app", "models", "OPNsense", "Blocky",
                                                "Blocky.xml")).getroot().find("items"))


class Helpers:
    """The part of OPNsense's template helpers config.yml uses."""

    def __init__(self, config):
        self.config = config

    def _node(self, path):
        node = self.config
        for part in path.split("."):
            node = node.get(part) if isinstance(node, dict) else None
        return node

    def exists(self, path):
        return self._node(path) is not None

    def toList(self, path):
        return list(self._node(path) or [])


def render(**sections):
    """Render with the defaults, one enabled upstream, and the given sections merged in."""
    blocky = copy.deepcopy(DEFAULTS)
    blocky["general"]["enabled"] = "1"
    blocky["upstreams"] = [{"enabled": "1", "group": "default", "server": "1.1.1.1"}]
    for name, values in sections.items():
        if isinstance(values, dict):
            blocky[name].update(values)
        else:
            blocky[name] = values
    config = {"OPNsense": {"blocky": blocky}}
    # the same environment core's template engine builds
    env = jinja2.Environment(loader=jinja2.FileSystemLoader(TEMPLATES), trim_blocks=True,
                             extensions=["jinja2.ext.do", "jinja2.ext.loopcontrols"])
    text = env.get_template("OPNsense/Blocky/config.yml").render(helpers=Helpers(config), **config)
    return yaml.safe_load(text)


def denylist(source):
    return [{"enabled": "1", "group": "ads", "source": source}]


class Template(unittest.TestCase):
    def test_defaults(self):
        doc = render()
        self.assertEqual(doc["upstreams"]["groups"], {"default": ["1.1.1.1"]})
        self.assertEqual(doc["ports"]["dns"], "53")
        self.assertNotIn("http", doc["ports"], "the unauthenticated HTTP API is off by default")
        for key in ("certFile", "keyFile", "redis"):
            self.assertNotIn(key, doc)
        self.assertEqual(doc["pprof"], {"enable": True}, "Blocky's default")
        self.assertIs(doc["prometheus"]["enableClientLabel"], True, "Blocky's default")

    def test_profiler_can_be_turned_off(self):
        self.assertEqual(render(general={"pprof": "0"})["pprof"], {"enable": False})

    def test_client_label_can_be_turned_off(self):
        self.assertIs(render(general={"prometheusClientLabel": "0"})["prometheus"]["enableClientLabel"], False)

    def test_ignored_clients(self):
        doc = render(queryLog={"type": "console", "ignoreClients": "192.168.1.1,10.0.0.0/8,*-ap"})
        self.assertEqual(doc["queryLog"]["ignore"], {"clients": ["192.168.1.1", "10.0.0.0/8", "*-ap"]})
        self.assertNotIn("ignore", render(queryLog={"type": "none", "ignoreClients": "192.168.1.1"})["queryLog"])

    def test_free_text_stays_a_value(self):
        # each value tries to open a top-level section of its own; none may appear
        cases = [
            {"queryLog": {"type": "console", "ignoreDomains": "x.lan'\nredis:\n  address: 'evil"}},
            {"general": {"cacheExclude": "/a'/\nredis:\n  address: evil"}},
            {"general": {"userAgent": "ua'\nredis:\n  address: evil"}},
            {"general": {"customZone": "host IN A 10.0.0.1\nredis:\n  address: evil"}},
            {"hostsFile": {"sources": "a.lan\nredis:\n  address: evil"}},
        ]
        for case in cases:
            doc = render(**case)
            self.assertNotIn("redis", doc, case)
        doc = render(general={"cacheExclude": "/it's/"}, queryLog={"type": "console", "ignoreDomains": "o'brien.lan"},
                     redis={"address": "r:6379", "password": "p'w\nstatistics:\n  enable: true"})
        self.assertEqual(doc["caching"]["exclude"], ["/it's/"])
        self.assertEqual(doc["queryLog"]["ignore"]["domains"], ["o'brien.lan"])
        self.assertNotIn("statistics", doc)

    def test_fixed_write_paths(self):
        doc = render(general={"downloadCache": "1"}, denylists=denylist("https://example.com/list.txt"),
                     hostsFile={"sources": "/etc/hosts", "downloadCache": "1"}, queryLog={"type": "csv"})
        self.assertEqual(doc["blocking"]["loading"]["downloads"]["cachePath"], "/var/cache/blocky/lists")
        self.assertEqual(doc["hostsFile"]["loading"]["downloads"]["cachePath"], "/var/cache/blocky/hosts")
        self.assertEqual(doc["queryLog"]["target"], "/var/db/blocky/querylog")
        self.assertEqual(render(queryLog={"type": "sqlite", "target": "/etc/x"})["queryLog"]["target"],
                         "/var/db/blocky/querylog.db")
        self.assertNotIn("cachePath", render(denylists=denylist("a.lan"))["blocking"]["loading"]["downloads"])

    def test_logs_to_syslog_as_blocky(self):
        # the log page and remote logging match program "blocky"
        log = render()["log"]
        self.assertEqual(log["target"], "syslog")
        self.assertEqual(log["syslog"], {"tag": "blocky"})

    def test_database_target_is_taken_as_given(self):
        doc = render(queryLog={"type": "postgresql", "target": "postgres://u:p@db/blocky"})
        self.assertEqual(doc["queryLog"]["target"], "postgres://u:p@db/blocky")

    def test_list_entries(self):
        doc = render(denylists=denylist("/usr/local/etc/blocky/lists/mine.txt") + denylist("ads.example.com"))
        self.assertEqual(doc["blocking"]["denylists"]["ads"],
                         ["/usr/local/etc/blocky/lists/mine.txt", "ads.example.com\n"])

    def test_sentinel_only_with_addresses(self):
        redis = {"address": "r:6379", "sentinelPassword": "s"}
        self.assertNotIn("sentinelPassword", render(redis=redis)["redis"])
        with_sentinels = render(redis=dict(redis, sentinelAddresses="s1:26379"))["redis"]
        self.assertEqual(with_sentinels["sentinelPassword"], "s")

    def test_zone_first_line_indented(self):
        zone = "  IN A 10.0.0.1\nhost IN A 10.0.0.2"
        self.assertEqual(render(general={"customZone": zone})["customDNS"]["zone"], zone + "\n")

    def test_certificate_from_trust_store(self):
        doc = render(general={"certificate": "abc123"})
        self.assertEqual((doc["certFile"], doc["keyFile"]),
                         ("/usr/local/etc/blocky/cert.pem", "/usr/local/etc/blocky/key.pem"))

    def test_a_query_type_that_is_a_yaml_keyword(self):
        self.assertEqual(render(filtering={"queryTypes": "A,NULL"})["filtering"]["queryTypes"], ["A", "NULL"])

    def test_a_domain_starting_with_http_stays_inline(self):
        # blocky takes a bare httpbin.org as a download; as a block it is text
        doc = render(denylists=denylist("httpbin.org") + denylist("https://example.com/l.txt"),
                     hostsFile={"sources": "http-ads.lan"})
        self.assertEqual(doc["blocking"]["denylists"]["ads"], ["httpbin.org\n", "https://example.com/l.txt"])
        self.assertEqual(doc["hostsFile"]["sources"], ["http-ads.lan\n"])

    def test_a_document_marker_in_free_text(self):
        doc = render(general={"userAgent": "ua\n---\nredis:\n  address: evil"})
        self.assertEqual(doc["upstreams"]["userAgent"], "ua --- redis:   address: evil")
        self.assertNotIn("redis", doc)

    def test_entries_for_one_domain_are_combined(self):
        rows = [{"enabled": "1", "domain": "a.lan", "ip": "10.0.0.1"}, {"enabled": "1", "domain": "b.lan", "ip": "10.0.0.3"},
                {"enabled": "1", "domain": "a.lan", "ip": "10.0.0.2"}, {"enabled": "0", "domain": "a.lan", "ip": "10.0.0.9"}]
        forwards = [{"enabled": "1", "domain": "x.lan", "resolver": "10.0.0.1"},
                    {"enabled": "1", "domain": "x.lan", "resolver": "10.0.0.2"}]
        doc = render(customdns=rows, conditional=forwards)
        self.assertEqual(doc["customDNS"]["mapping"], {"a.lan": "10.0.0.1,10.0.0.2", "b.lan": "10.0.0.3"})
        self.assertEqual(doc["conditional"]["mapping"], {"x.lan": "10.0.0.1,10.0.0.2"})

    def test_domains_as_blocky_matches_them(self):
        # Blocky folds case, and keeps one of two such keys at random; a trailing dot never matches
        rows = [{"enabled": "1", "domain": "NAS.lan", "ip": "10.0.0.1"}, {"enabled": "1", "domain": "nas.lan.", "ip": "10.0.0.2"}]
        forwards = [{"enabled": "1", "domain": "Home.Arpa.", "resolver": "10.0.0.1"},
                    {"enabled": "1", "domain": ".", "resolver": "10.0.0.2"}]
        rewrites = [{"enabled": "1", "fromDomain": "Fritz.Box.", "toDomain": "fritz.lan"}]
        doc = render(customdns=rows, conditional=forwards, customdnsrewrite=rewrites)
        self.assertEqual(doc["customDNS"]["mapping"], {"nas.lan": "10.0.0.1,10.0.0.2"})
        self.assertEqual(doc["conditional"]["mapping"], {"home.arpa": "10.0.0.1", ".": "10.0.0.2"})
        self.assertEqual(doc["customDNS"]["rewrite"], {"fritz.box": "fritz.lan"})
        # two rows one key, as an earlier version could store: the one Blocky matched stays, else the first
        rewrites.append({"enabled": "1", "fromDomain": "fritz.box", "toDomain": "other.lan"})
        rewrites.append({"enabled": "1", "fromDomain": "Fritz.Box", "toDomain": "third.lan"})
        self.assertEqual(render(customdnsrewrite=rewrites)["customDNS"]["rewrite"], {"fritz.box": "other.lan"})
        doc = render(conditional=forwards, conditionalrewrite=rewrites)
        self.assertEqual(doc["conditional"]["rewrite"], {"fritz.box": "other.lan"})
        forwards.append({"enabled": "1", "domain": "home.arpa", "resolver": "10.0.0.3"})
        self.assertEqual(render(conditional=forwards)["conditional"]["mapping"], {"home.arpa": "10.0.0.3", ".": "10.0.0.2"})

    def test_addresses_stay_text(self):
        # unquoted, fd00:: would be a key
        doc = render(clientlookupclients=[{"enabled": "1", "name": "nas", "ips": "fd00::,10.0.0.5"}],
                     bootstrap=[{"enabled": "1", "type": "resolver", "content": "tcp-tls:dns.quad9.net", "ips": "2620:fe::"}])
        self.assertEqual(doc["clientLookup"]["clients"], {"nas": ["fd00::", "10.0.0.5"]})
        self.assertEqual(doc["bootstrapDns"][0]["ips"], ["2620:fe::"])

    def test_server_timeouts_without_lists(self):
        # Blocky's own HTTP server takes them from blocking.loading.downloads, lists or not
        doc = render(general={"downloadWriteTimeout": "45s"})
        self.assertNotIn("denylists", doc["blocking"])
        self.assertEqual(doc["blocking"]["loading"]["downloads"]["writeTimeout"], "45s")

    def test_an_empty_trust_anchor_is_left_out(self):
        anchor = ". 172800 IN DNSKEY 257 3 8 AwEAA"
        doc = render(dnssec={"validate": "1", "trustAnchors": anchor + ", "})
        self.assertEqual(doc["dnssec"]["trustAnchors"], [anchor])


if __name__ == "__main__":
    unittest.main()
