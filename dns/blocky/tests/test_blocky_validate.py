"""Whatever the model accepts, Blocky accepts, or refuses with a reason of its own that Apply shows:
values are swept through every field, the model decides which it takes, core's template engine
renders those, and `blocky validate` checks each.

Needs OPNSENSE_CORE, php and a blocky binary (BLOCKY, or blocky on PATH) of the pinned version."""

import atexit
import concurrent.futures
import hashlib
import json
import os
import random
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET

HERE = os.path.dirname(os.path.abspath(__file__))
PLUGIN = os.path.join(HERE, "..", "src", "opnsense")
MODEL = os.path.join(PLUGIN, "mvc", "app", "models", "OPNsense", "Blocky", "Blocky.xml")
TEMPLATES = os.path.join(PLUGIN, "service", "templates") + "/"
CORE = os.environ.get("OPNSENSE_CORE")
SCRIPTS = os.path.join(PLUGIN, "scripts", "OPNsense", "Blocky")
BLOCKY = os.environ.get("BLOCKY") or shutil.which("blocky")

# values that fit some field, values YAML reads as something else, and values that break quoting
POOL = [
    "", "0", "1", "2", "5", "10", "53", "100", "1000", "65535", "65536", "-1", "-5", "99999999999",
    "0s", "2s", "500ms", "1m", "1h30m", "10ns", "5us", "1d", "1.5s", "12:30", "00:00", "23:59", "24:00",
    "1.2", "1.3", "1.1.1.1", "::1", "fe80::1", "2001:db8::1", "10.0.0.0/8", "2001:db8::/32", "0.0.0.0, ::",
    "1.1.1.1,9.9.9.9", "tcp-tls:1.1.1.1:853", "tcp+udp:[2606:4700::1111]:53", "udp:dns.quad9.net",
    "https://dns.google/dns-query", "quic:dns.adguard-dns.com", "sdns://AgcAAAAAAAAABzEuMC4wLjE",
    "127.0.0.1:6379", "[::1]:53", ":53", "localhost:6379", "mymaster", "redis.lan:6379,redis2.lan:6379",
    "zeroIP", "nxDomain", "refused", "default", "ads", "ads,malware", "kids", "client[1-3]", "*.lan",
    "example.com", "ads.example.com", "fritz.box", "lan", "DE", "NL-X", "/metrics", "/", "/a/b.c",
    "/^ad[sx]?\\./", "/it's/", "https://example.com/list.txt", "/usr/local/etc/blocky/lists/mine.txt",
    "file:///usr/local/etc/blocky/lists/mine.txt", "/etc/hosts", "file:/usr/local/etc/blocky/secrets/x",
    "tcp://127.0.0.1:6000", "postgres://u:p@db/blocky", "user:pass@tcp(db:3306)/blocky", "host IN A 10.0.0.1",
    "  IN A 10.0.0.1\nhost IN A 10.0.0.2", "$TTL 3600\n@ IN A 10.0.0.1", "  IN A 10.0.0.1\nh.lan. IN A 10.0.0.2",
    "udp:1.1.1.1", "tcp:1.1.1.1", "tcp-tls://1.1.1.1", "HTTPS://dns.google/dns-query", "1.1.1.1:99999",
    "tcp-tls:1.1.1.1:0", "SDNS://AAcAAAAAAAAABzEuMS4xLjE",
    "sdns://AAAAAAAAAAAABzEuMS4xLjE",
    "sdns://AAAAAAAAAAAADDEuMS4xLjE6NTM1Mw",
    "sdns://AgAAAAAAAAAABzEuMS4xLjEAEmNsb3VkZmxhcmUtZG5zLmNvbQovZG5zLXF1ZXJ5",
    "sdns://AwAAAAAAAAAABzEuMS4xLjEAD29uZS5vbmUub25lLm9uZQ",
    "sdns://BAAAAAAAAAAAAAAXZG5zLmFkZ3VhcmQtZG5zLmNvbTo4NTM",
    "sdns://AQAAAAAAAAAABzEuMS4xLjEgeHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHgRMi5kbnNjcnlwdC1jZXJ0Lng",
    "sdns://AwAAAAAAAAAABzEuMS4xLjEACWJhZCBob3N0IQ",
    "sdns://AgAAAAAAAAAABzEuMS4xLjEABXguY29t",
    "sdns://AAAAAAAAAAAABzEuMS4xLjFqdW5r",
    "yes", "no", "on", "off", "true", "false", "null", "~", ".inf", ".nan", "0x1F", "0o17", "1e3", "1_000", "01",
    "'q'", '"dq"', "a: b", "- a", "# c", "{a}", "[a]", "&a", "*a", "!a", "|", "> x", "%x", "@x", "`x`",
    "a b", " lead", "trail ", "tab\tx", "back\\slash", "é", "日本", "x\nredis:\n  address: evil", "a,,b", ",",
]

# enough values from each sweep to build rich baselines and random combinations from
SEED = 20260925
RANDOM_CASES = 400

# what the template writes from no field the import could fill: fixed paths and logging
WRITTEN_FROM_NO_FIELD = {"certFile", "keyFile", "log.timestamp", "log.target", "log.syslog",
                         "blocking.loading.downloads.cachePath", "hostsFile.loading.downloads.cachePath"}

# Blocky's own reasons for the checks left to it, which Apply shows (deploy.sh)
LEFT_TO_BLOCKY = re.compile(r"invalid duration|unknown DNS query type|can't convert upstream|"
                            r"ports\.proxyProtocol includes|rateLimit: |DNS64")


def model_fields():
    """(scalar fields as {ref: node}, arrays as {name: [(field, node)]}) from the model XML."""
    scalars, arrays = {}, {}

    def walk(node, path):
        for child in node:
            ref = ".".join(path + [child.tag])
            kind = child.get("type")
            if kind == "ArrayField":
                arrays[ref] = [(f.tag, f) for f in child]
            elif kind == "CertificateField":
                continue  # needs core's trust store, which the harness has not got
            elif ref == "general.customZone":
                continue  # left to Blocky, which checks it before Apply puts it in place
            elif kind:
                scalars[ref] = child
            else:
                walk(child, path + [child.tag])

    walk(ET.parse(MODEL).getroot().find("items"), [])
    return scalars, arrays


def candidates(node):
    """Pool values plus the field's own options and bounds."""
    values = list(POOL)
    options = node.find("OptionValues")
    if options is not None:
        values += [o.get("value", o.tag) for o in options]
    for bound in ("MinimumValue", "MaximumValue"):
        text = node.findtext(bound)
        if text:
            values += [text, str(int(text) - 1), str(int(text) + 1)]
    if node.findtext("Default") is not None:
        values.append(node.findtext("Default"))
    return list(dict.fromkeys(values))


def run_model(cases):
    """The model's verdict on each case: (messages as {field: text}, config.xml text or None)."""
    return [({field: text for field, text in r["messages"]}, r["xml"]) for r in harness(cases)]


def run_import(texts):
    """importAction's verdict on each config.yml: (what it left out, errors, config.xml text or None)."""
    return [(r["import"]["left"], r["import"]["errors"], r["xml"]) for r in harness([imported(t) for t in texts])]


def harness(cases):
    """model_harness.php's answer for each case."""
    if len(cases) > 500:
        with concurrent.futures.ThreadPoolExecutor(os.cpu_count() or 2) as pool:
            chunks = pool.map(harness, [cases[i:i + 500] for i in range(0, len(cases), 500)])
            return [r for chunk in chunks for r in chunk]
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as handle:
        handle.write(json.dumps(cases))  # one write: dump() writes piecemeal, which is slow
    try:
        run = subprocess.run(["php", os.path.join(HERE, "model_harness.php"), handle.name],
                             capture_output=True, text=True)
    finally:
        os.unlink(handle.name)
    out = run.stdout
    assert run.returncode == 0, (run.stdout + run.stderr)[-2000:]
    results = [json.loads(line) for line in out.splitlines() if line.startswith("{")]
    assert len(results) == len(cases), out[-2000:]
    return results


class Renderer:
    """config.yml exactly as configd writes it: core's config reader and template engine."""

    def __init__(self, target):
        sys.path.insert(0, os.path.join(CORE, "src", "opnsense", "service"))
        import jinja2
        from modules import config, template
        self.config, self.target = config, target
        self.engine = template.Template(target)
        self.engine._template_dir = TEMPLATES
        self.engine._j2_env.loader = jinja2.FileSystemLoader(TEMPLATES)

    def render(self, xml):
        path = os.path.join(self.target, "config.xml")
        with open(path, "w") as handle:
            handle.write(xml)
        self.engine.set_config(self.config.Config(path).get())
        self.engine._generate("OPNsense/Blocky")
        # staged: Blocky's start puts it in place once Blocky takes it (deploy.sh)
        with open(os.path.join(self.target, "usr", "local", "etc", "blocky", "config.yml.staging")) as handle:
            return handle.read()


# one per process: a worker forked after the main process rendered must not share its folder
RENDERERS = {}


def rendered(xml):
    """(config.yml, None), or (None, why it did not render), in a worker process."""
    renderer = RENDERERS.get(os.getpid())
    if renderer is None:
        target = tempfile.mkdtemp()
        atexit.register(shutil.rmtree, target, True)
        renderer = RENDERERS[os.getpid()] = Renderer(target)
    try:
        return renderer.render(xml), None
    except Exception as error:
        return None, str(error)


def imported(text):
    """The importer's output for a config.yml, as a harness case applying it to an enabled Blocky
    (run in a worker process)."""
    if SCRIPTS not in sys.path:
        sys.path[:0] = [SCRIPTS, os.path.join(SCRIPTS, "lib")]
    from import_config import Mapper, load
    return {"fields": {"general.enabled": "1"}, "rows": {}, "import": Mapper(load(text)).run()}


def blocky_validate(text):
    """None when Blocky takes the config, else its reason."""
    with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False) as handle:
        handle.write(text)
    try:
        run = subprocess.run([BLOCKY, "validate", "--config", handle.name], capture_output=True, text=True)
    finally:
        os.unlink(handle.name)
    if run.returncode == 0:
        return None
    lines = [line.strip() for line in (run.stdout + run.stderr).splitlines()
             if line.strip() and " WARN " not in line and " INFO " not in line]
    return " ".join(lines).replace(handle.name, "config.yml")[:400]


@unittest.skipUnless(CORE and BLOCKY and shutil.which("php"), "needs OPNSENSE_CORE, php and blocky")
class BlockyValidates(unittest.TestCase):
    def test_accepted_settings_are_valid_blocky_config(self):
        scalars, arrays = model_fields()
        base = {"fields": {"general.enabled": "1"},
                "rows": {"upstreams": [{"enabled": "1", "group": "default", "server": "1.1.1.1"}]}}

        def case(fields=None, rows=None, start=base):
            merged = {"fields": dict(start["fields"], **(fields or {})),
                      "rows": {k: list(v) for k, v in start["rows"].items()}}
            for name, extra in (rows or {}).items():
                merged["rows"][name] = merged["rows"].get(name, []) + extra
            return merged

        # a minimal accepted row per array, in model order on top of the rows before it, since
        # e.g. a schedule names a group a deny list defined: each field takes the first value the
        # model takes there, and a row the model still refuses is left out of the joint baseline
        row_base, joint = {}, {}
        for name, fields in arrays.items():
            row = {"enabled": "1"}
            for field, node in fields:
                if field == "enabled":
                    continue
                values = candidates(node)
                verdicts = run_model([case(rows=dict(joint, **{name: [dict(row, **{field: v})]})) for v in values])
                index = len(base["rows"].get(name, []))
                taken = [v for v, (msgs, _) in zip(values, verdicts)
                         if f"{name}.{index}.{field}" not in msgs and v != ""]
                if taken:
                    row[field] = taken[0]
            row_base[name] = row
            if run_model([case(rows=dict(joint, **{name: [row]}))])[0][1] is not None:
                joint[name] = [row]

        def sweep(start):
            """Every candidate in every field, alone on top of start: {(where, value): case}."""
            cases = {}
            for ref, node in scalars.items():
                for value in candidates(node):
                    cases[(ref, value)] = case({ref: value}, start=start)
            for name, fields in arrays.items():
                for field, node in fields:
                    for value in candidates(node):
                        cases[(f"{name}[].{field}", value)] = case(
                            rows={name: [dict(row_base[name], **{field: value})]}, start=start)
            return cases

        failures, configs = {}, {}

        def blocky_verdicts(cases):
            """{(where, value): (config.yml, None when Blocky takes it, else its reason)} for each case
            the model accepts; a template that does not render is a failure too."""
            results = run_model([c for _, c in cases])
            accepted = [(key, xml) for (key, _), (_, xml) in zip(cases, results) if xml is not None]
            with concurrent.futures.ProcessPoolExecutor(os.cpu_count() or 2) as pool:
                texts = list(pool.map(rendered, [xml for _, xml in accepted], chunksize=50))
            distinct = {}
            for (key, _), (text, error) in zip(accepted, texts):
                if error is not None:
                    failures.setdefault(key[0], []).append((key[1], f"render: {error}"))
                else:
                    distinct.setdefault(hashlib.sha256(text.encode()).hexdigest(), (text, []))[1].append(key)
            configs.update(distinct)
            verdicts = {}
            with concurrent.futures.ThreadPoolExecutor(8) as pool:
                for (text, keys), reason in zip(distinct.values(), pool.map(blocky_validate, [t for t, _ in distinct.values()])):
                    for key in keys:
                        verdicts[key] = (text, reason)
                    # whether a file the model allows exists is for Apply to say, as are the checks
                    # left to Blocky, whose reason Apply shows
                    if reason is not None and not re.search(r"failed to read secret file .*: no such file or "
                                                            r"directory", reason) and not LEFT_TO_BLOCKY.search(reason):
                        failures.setdefault(keys[0][0], []).append((keys[0][1], reason))
            return verdicts

        first = sweep(base)
        verdicts = blocky_verdicts(list(first.items()))
        # what the model and Blocky both take, to build on
        taken = {}
        for (where, value), (_, reason) in verdicts.items():
            if reason is None:
                taken.setdefault(where, []).append(value)

        # a rich baseline: one of every row, then each field on something other than its default
        rows = case(rows=joint)
        choices = {ref: [v for v in taken.get(ref, []) if v not in ("", node.findtext("Default") or "")][:3]
                   for ref, node in scalars.items()}
        choices = {ref: values for ref, values in choices.items() if values}
        # all at once, moving each field the model names to its next choice until it takes the lot
        while True:
            messages, xml = run_model([case({ref: values[0] for ref, values in choices.items()}, start=rows)])[0]
            named = [ref for ref in messages if ref in choices]
            if xml is not None or not named:
                break
            for ref in named:
                choices[ref] = choices[ref][1:]
                if not choices[ref]:
                    del choices[ref]
        rich = case({ref: values[0] for ref, values in choices.items()}, start=rows)
        # a rule across fields no single field answers for, the model's or Blocky's
        if xml is None or blocky_validate(rendered(xml)[0] or "") is not None:
            rich = rows

        cases = list(sweep(rich).items())
        rng = random.Random(SEED)
        for n in range(RANDOM_CASES):
            fields = {ref: rng.choice(values) for ref, values in taken.items()
                      if "[]" not in ref and rng.random() < 0.3}
            rows = {}
            for name, fields_of in arrays.items():
                if rng.random() < 0.5:
                    row = dict(row_base[name])
                    for field, _ in fields_of:
                        choices = taken.get(f"{name}[].{field}")
                        if choices and rng.random() < 0.5:
                            row[field] = rng.choice(choices)
                    rows[name] = [row]
            cases.append(((f"random#{n}", ""), case(fields, rows, start=rich)))
        verdicts.update(blocky_verdicts(cases))

        # a config Blocky runs imports whole: the importer's output, applied as importAction does
        valid = {text: key for key, (text, reason) in verdicts.items() if reason is None}
        with concurrent.futures.ProcessPoolExecutor(os.cpu_count() or 2) as pool:
            imports = list(pool.map(imported, list(valid), chunksize=50))
        for (where, value), case, result in zip(valid.values(), imports, harness(imports)):
            for text in result["import"]["left"] + result["import"]["errors"]:
                failures.setdefault(f"import {where}", []).append((value, text))
            for key in set(case["import"]["skipped"]) - WRITTEN_FROM_NO_FIELD:
                failures.setdefault(f"import {where}", []).append((value, f"{key}: not read back"))

        report = "\n".join(f"{where}: {len(found)} value(s), e.g.\n" + "\n".join(
            f"    {value!r}: {reason}" for value, reason in found[:3]) for where, found in failures.items())
        self.assertFalse(failures, f"Blocky rejects settings the model accepts in {len(failures)} field(s) "
                                   f"({len(configs)} distinct configs checked):\n{report}")


@unittest.skipUnless(CORE and shutil.which("php"), "needs OPNSENSE_CORE and php")
class ModelRefuses(unittest.TestCase):
    """Settings Blocky exits on are refused by the model, with the message on a row a dialog shows."""

    DEFAULT = {"general.enabled": "1"}
    UPSTREAM = {"enabled": "1", "group": "default", "server": "1.1.1.1"}
    DOH_STAMP = "sdns://AgcAAAAAAAAABzEuMC4wLjEAEmNsb3VkZmxhcmUtZG5zLmNvbQovZG5zLXF1ZXJ5"

    def messages(self, fields=None, **rows):
        rows.setdefault("upstreams", [self.UPSTREAM])
        return run_model([{"fields": dict(self.DEFAULT, **(fields or {})), "rows": rows}])[0][0]

    def test_spaces_around_list_items(self):
        # as pasted or sent: the template, the model's own checks and Blocky trim each item
        anchor = ". 172800 IN DNSKEY 257 3 8 AwEAA"
        fields = {"dnssec.validate": "1", "dnssec.trustAnchors": anchor + ", " + anchor + ", ",
                  "queryLog.ignoreDomains": "a.com, *.b.com, ", "queryLog.ignoreClients": "10.0.0.1, nas, ",
                  "redis.address": "m", "redis.sentinelAddresses": "h1:26379, h2:26379, "}
        found = self.messages(fields, conditional=[{"enabled": "1", "domain": "lan", "resolver": "10.0.0.1, 10.0.0.2"}])
        for field in list(fields) + ["conditional.0.resolver"]:
            self.assertNotIn(field, found)
        found = self.messages({"queryLog.ignoreClients": "10.0.0.1, a b", "redis.address": "m",
                               "redis.sentinelAddresses": "h1:26379, /tmp/s.sock"},
                              conditional=[{"enabled": "1", "domain": "lan", "resolver": "10.0.0.1, "}])
        for field in ("queryLog.ignoreClients", "redis.sentinelAddresses", "conditional.0.resolver"):
            self.assertIn(field, found)

    def test_trust_anchors(self):
        def refused(anchor):
            return "dnssec.trustAnchors" in self.messages({"dnssec.validate": "1", "dnssec.trustAnchors": anchor})
        for anchor in (". 172800 IN DNSKEY 257 3 8 AwEAAaz/tAm8yTn4Mfeh AwEB", "@ 2d IN DNSKEY 257 3 13 mdss ; corp KSK",
                       "example. IN 3600 DNSKEY 257 3 13 mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJ=="):
            self.assertFalse(refused(anchor), anchor)
        # the first DNSKEY is the record, and a key may run over lines
        self.assertFalse(refused(". 172800 IN DNSKEY 257 3 8 AwEAA\nAwEB"))
        for anchor in (". 172800 IN DNSKEY 256 3 8 AwEAA", ". 172800 IN DNSKEY 256 3 8 AwEAA DNSKEY 257 3 8 AwEAA",
                       "DNSKEY 257 3 8 AwEAA", ". 172800 IN DS 20326 8 2 E06D44B8",
                       # Blocky parses these numbers only once it serves, and exits on one out of range
                       ". 172800 IN DNSKEY 257 x 8 AwEAA", ". 172800 IN DNSKEY 257 3 256 AwEAA",
                       ". 172800 IN DNSKEY 65537 3 8 AwEAA"):
            self.assertTrue(refused(anchor), anchor)

    def test_dnssec_limits_blocky_reads_as_defaults(self):
        for field in ("dnssec.cacheExpirationHours", "dnssec.maxNSEC3Iterations"):
            self.assertIn(field, self.messages({field: "0"}), field)

    def migrated(self, fields, migrations=("M1_0_6",), after=None, **rows):
        """Migrations on values as an earlier version stored them, then what a later save changes:
        (messages, config.xml as saved)."""
        rows.setdefault("upstreams", [self.UPSTREAM])
        messages, xml = run_model([{"fields": fields, "rows": rows, "migrate": list(migrations), "after": after or {}}])[0]
        return messages, ET.fromstring(xml) if xml else None

    def test_switching_a_row_on_checks_what_it_reads(self):
        """A row switched off for a file outside the plugin's directories stays off until the file is."""
        for section, row, field in (("denylists", {"enabled": "0", "group": "ads", "source": "/etc/master.passwd"}, "source"),
                                    ("bootstrap", {"enabled": "0", "type": "resolvfile", "content": "/etc/resolv.conf"}, "content")):
            messages, _ = self.migrated({}, after={f"{section}.0.enabled": "1"}, **{section: [row]})
            self.assertIn(f"{section}.0.{field}", messages, section)

    def test_what_blocky_exits_on(self):
        self.assertIn("general.blockType", self.messages({"general.blockType": "beef"}))
        self.assertIn("general.blockType", self.messages({"general.blockType": "999.1.1.1"}))
        for mode in ("ZEROIP", "NxDomain", "::ffff:192.0.2.1", "0.0.0.0, ::"):
            self.assertNotIn("general.blockType", self.messages({"general.blockType": mode}), "Blocky takes " + mode)
        self.assertNotIn("general.blockType", self.messages({"general.blockType": "0.0.0.0, ::"}))
        self.assertIn("queryLog.flushInterval", self.messages({"queryLog.type": "mysql", "queryLog.target": "u:p@tcp(db)/b",
                                                               "queryLog.flushInterval": "0s"}))
        self.assertIn("queryLog.flushInterval", self.messages({"queryLog.type": "sqlite", "queryLog.flushInterval": "0m0s"}))
        self.assertNotIn("queryLog.flushInterval", self.messages({"queryLog.type": "csv", "queryLog.flushInterval": "0s"}),
                         "only a database log writes on a timer")
        self.assertIn("bootstrap.0.ips", self.messages(bootstrap=[{"enabled": "1", "type": "resolver", "content": self.DOH_STAMP}]))
        self.assertNotIn("bootstrap.0.ips", self.messages(bootstrap=[{"enabled": "1", "type": "resolver", "content": self.DOH_STAMP,
                                                                      "ips": "1.0.0.1"}]))
        self.assertNotIn("bootstrap.0.ips", self.messages(bootstrap=[{"enabled": "1", "type": "resolver",
                                                                      "content": "sdns://AAcAAAAAAAAABzEuMS4xLjE"}]),
                         "a plain stamp carries its address")

    @unittest.skipUnless(BLOCKY, "needs blocky")
    def test_what_blocky_says_why_on_apply(self):
        """Left to Blocky, whose own reason Apply shows (deploy.sh): the model takes these, Blocky does not."""
        dotted = "tcp-tls:dns.quad9.net."
        for fields, rows in (({"general.timeout": "2562048h"}, {}),
                             ({"filtering.queryTypes": "FOO"}, {}), ({"general.proxyProtocol": "http"}, {}),
                             ({"rateLimit.enable": "1", "rateLimit.rate": "0"}, {}),
                             ({"rateLimit.enable": "1", "rateLimit.rate": "10", "rateLimit.burst": "5"}, {}),
                             ({"dns64.enable": "1", "filtering.queryTypes": "AAAA"}, {}),
                             ({"dns64.enable": "1", "dns64.prefix": "64:ff9b::/33"}, {}),
                             ({"general.clientLookupUpstream": dotted}, {}),
                             ({}, {"upstreams": [self.UPSTREAM, dict(self.UPSTREAM, server=dotted)]}),
                             ({}, {"conditional": [{"enabled": "1", "domain": "lan", "resolver": dotted}]}),
                             ({}, {"bootstrap": [{"enabled": "1", "type": "resolver", "content": dotted, "ips": "9.9.9.9"}]}),
                             ({"dns64.enable": "1", "dns64.prefix": "any"}, {}),
                             ({"rateLimit.enable": "1", "rateLimit.rate": "10", "rateLimit.allowlist": "any"}, {}),
                             ({}, {"customdns": [{"enabled": "1", "domain": "nas.lan", "ip": "any"}]})):
            rows.setdefault("upstreams", [self.UPSTREAM])
            messages, xml = run_model([{"fields": dict(self.DEFAULT, **fields), "rows": rows}])[0]
            self.assertEqual(messages, {}, (fields, rows))
            text, error = rendered(xml)
            self.assertIsNone(error)
            self.assertIsNotNone(blocky_validate(text), (fields, rows))

    def test_a_key_given_twice_names_a_row(self):
        rows = [{"enabled": "1", "fromDomain": "a.lan", "toDomain": "b.lan"}, {"enabled": "1", "fromDomain": "A.lan.", "toDomain": "c.lan"}]
        found = self.messages(customdnsrewrite=rows)
        self.assertIn("customdnsrewrite.1.fromDomain", found, "a dialog shows the message on the row it edits")
        # stored twice by an earlier version: the template keeps the first, and a save of anything
        # else, such as an upgrade's, goes through
        messages, _ = self.migrated({}, customdnsrewrite=rows)
        self.assertEqual(messages, {})

    def test_an_upgrade_gives_dnssec_limits_their_defaults(self):
        messages, root = self.migrated({"dnssec.cacheExpirationHours": "0", "dnssec.maxNSEC3Iterations": "0"})
        self.assertEqual(messages, {})
        self.assertEqual(root.findtext(".//dnssec/cacheExpirationHours"), "1")
        self.assertEqual(root.findtext(".//dnssec/maxNSEC3Iterations"), "150")

    def test_what_blocky_runs_with(self):
        # Blocky runs without Redis when it has no address, logs a group without lists and falls back to
        # the console without a log target; the template writes a schedule without both times as all day
        self.assertEqual(self.messages(
            {"redis.required": "1", "queryLog.type": "mysql"},
            clientgroups=[{"enabled": "1", "client": "default", "groups": "missing"}],
            schedules=[{"enabled": "1", "name": "a", "weekdays": "mon", "groups": "missing", "start": "08:00"},
                       {"enabled": "1", "name": "b", "weekdays": "mon", "groups": "missing", "start": "08:00", "end": "08:00"}]), {})

    def test_a_dnstap_target_blocky_parses(self):
        """Blocky parses the target only once it serves (querylog/dnstap_writer.go parseDnstapTarget)."""
        def refused(target):
            return "queryLog.target" in self.messages({"queryLog.type": "dnstap", "queryLog.target": target})
        for target in ("tcp://127.0.0.1:6000", "tcp://[::1]:6000", "tcp://collector.lan:6000",
                       "file:/usr/local/etc/blocky/secrets/dnstap"):
            self.assertFalse(refused(target), target)
        # Blocky would connect to a Unix socket as root, so none is taken
        for target in ("127.0.0.1:6000", "tcp://", "tcp://127.0.0.1", "tcp://:6000", "tcp://::1:6000", "tcp://[::1]",
                       "unix:/var/run/configd.socket", "/var/run/dnstap.sock", "TCP://127.0.0.1:6000",
                       "file:/etc/master.passwd"):
            self.assertTrue(refused(target), target)
        self.assertNotIn("queryLog.target", self.messages({"queryLog.type": "mysql", "queryLog.target": "u:p@tcp(db)/b"}))

    def test_control_characters_in_a_list_source(self):
        # yaml.v2 refuses them written out, which Blocky would only say as a YAML error
        for source in ("a\x7fb.com", "a\x85b.com", "a\x01b.com"):
            self.assertIn("denylists.0.source", self.messages(denylists=[{"enabled": "1", "group": "ads", "source": source}]),
                          repr(source))
            self.assertIn("allowlists.0.source", self.messages(allowlists=[{"enabled": "1", "group": "ads", "source": source}]),
                          repr(source))

    def test_control_characters_blocky_refuses_anywhere(self):
        # Blocky's YAML parser refuses DEL and the C1 controls, naming no setting; the template writes
        # NEL, LS and PS as the space YAML would read, and core drops the C0 controls on save
        for char in ("\x7f", "\x80", "\x85", "\x9f", "\x00", "\x01", "\x1b", "\u2028", "\u2029"):
            value = f"a{char}b.lan"
            found = self.messages({"general.userAgent": value, "general.customZone": f"nas.lan. 60 IN A 10.0.0.1{char}",
                                   "redis.address": value, "general.clientLookupUpstream": value},
                                  upstreams=[self.UPSTREAM, dict(self.UPSTREAM, server=value)],
                                  clientgroups=[{"enabled": "1", "client": value, "groups": "ads"}],
                                  denylists=[{"enabled": "1", "group": "ads", "source": "ads.example.com"}])
            for field in ("general.userAgent", "general.customZone", "redis.address", "general.clientLookupUpstream",
                          "upstreams.1.server", "clientgroups.0.client"):
                self.assertIn(field, found, (repr(char), field))
        found = self.messages({"general.userAgent": "Mozilla/5.0 (é ∞ 日本)",
                               "general.customZone": "nas\tIN A 10.0.0.1\r\nnas.lan. 60 IN A 10.0.0.1\n"})
        self.assertNotIn("general.userAgent", found)
        self.assertNotIn("general.customZone", found)

    def test_every_listener_port(self):
        # blocky validate parses only the first DNS and HTTP listener; Blocky exits at start on the others
        for field in ("general.dnsPort", "general.httpPort", "general.tlsPort", "general.httpsPort"):
            for value, refused in (("53,65535", False), ("53,70000", True), ("127.0.0.1:65536", True),
                                   ("[::1]:99999", True), (":0", False)):
                self.assertEqual(field in self.messages({field: value}), refused, (field, value))

    def test_cache_exclusions_as_go_compiles_them(self):
        # Blocky compiles them with RE2 only once it serves, and exits on one it cannot; a comma splits one
        for value, refused in (("/\\.example\\.com$/", False), ("/^ad[sx]?\\./,/(?i)tracker/", False),
                               ("/a(b/", True), ("/(?=x)a/", True), ("/(a)\\1/", True), ("/a++/", True),
                               ("/a{1,3}/", True)):
            self.assertEqual("general.cacheExclude" in self.messages({"general.cacheExclude": value}), refused, value)

    def test_values_blocky_takes(self):
        # prefix 0 is one bucket for all clients, concurrency 0 no limit, -1 attempts no retries (go-redis)
        for fields in ({"rateLimit.enable": "1", "rateLimit.rate": "10", "rateLimit.ipv4Prefix": "0", "rateLimit.ipv6Prefix": "0"},
                       {"general.loadingConcurrency": "0", "hostsFile.concurrency": "0"},
                       {"redis.connectionAttempts": "-1"}, {"redis.connectionAttempts": "0"},
                       {"general.dohPath": "/dns~query/a:b@c", "general.prometheusPath": "/a:b@c"}):
            self.assertEqual(self.messages(fields), {}, fields)
        # names are written quoted; only the comma lists they appear in limit them
        self.assertEqual(self.messages(
            {}, customdns=[{"enabled": "1", "domain": "_dmarc.example.lan", "ip": "192.0.2.1"}],
            denylists=[{"enabled": "1", "group": "kids:1<b>", "source": "ads.example.com"}],
            clientgroups=[{"enabled": "1", "client": "default", "groups": "kids:1<b>"}],
            schedules=[{"enabled": "1", "name": "school: days", "weekdays": "mon", "groups": "kids:1<b>"}],
            clientlookupclients=[{"enabled": "1", "name": "nas:1", "ips": "192.0.2.2"}]), {})

    def test_what_blocky_cannot_route_or_retry(self):
        # chi panics at start on { or * in a route, and needs the leading slash Blocky checks only for DoH;
        # go-redis runs no command at all with fewer than -1 retries
        for fields, field in (({"general.dohPath": "/dns{x"}, "general.dohPath"), ({"general.dohPath": "/dns*"}, "general.dohPath"),
                              ({"general.prometheusPath": "metrics"}, "general.prometheusPath"),
                              ({"redis.connectionAttempts": "-2"}, "redis.connectionAttempts")):
            self.assertIn(field, self.messages(fields), fields)
        found = self.messages({}, denylists=[{"enabled": "1", "group": "a b", "source": "ads.example.com"},
                                             {"enabled": "1", "group": "a,b", "source": "ads.example.com"}])
        self.assertIn("denylists.0.group", found)
        self.assertIn("denylists.1.group", found)

    def test_a_zone_reads_no_file(self):
        # Blocky reads what an $INCLUDE names as root; the zone's own records need none. Go uppercases
        # the dotless ı to I, so $ınclude is one too
        for zone in ("$INCLUDE /etc/master.passwd", "nas.lan. 60 IN A 10.0.0.1\r\n  $include /dev/zero\n",
                     "$ınclude /etc/master.passwd", "$ıNCLUDE /etc/master.passwd"):
            self.assertIn("general.customZone", self.messages({"general.customZone": zone}), zone)
        for zone in ('nas.lan. 60 IN TXT "$INCLUDE x"\n', "$includes.lan. 60 IN A 10.0.0.1\n"):
            self.assertNotIn("general.customZone", self.messages({"general.customZone": zone}), zone)

    def test_lengths_blocky_reads(self):
        # a client is a YAML key, which may run to 1024 characters; a position is an unsigned integer
        lists = [{"enabled": "1", "group": "ads", "source": "ads.example.com"}]
        for client, refused in (("a" * 253, False), ("a" * 254, True)):
            found = self.messages(denylists=lists, clientgroups=[{"enabled": "1", "client": client, "groups": "ads"}])
            self.assertEqual("clientgroups.0.client" in found, refused, len(client))
        for order, refused in (("2,1", False), ("999", False), ("1000", True), ("99999999999999999999", True)):
            self.assertEqual("general.clientLookupOrder" in self.messages({"general.clientLookupOrder": order}), refused, order)

    @unittest.skipUnless(BLOCKY, "needs blocky")
    def test_integers_as_blocky_reads_them(self):
        # core's integer check takes a sign, which Blocky's ECS mask parser does not
        for mask in ("+5", "-0", "24"):
            messages, xml = run_model([{"fields": dict(self.DEFAULT, **{"ecs.useAsClient": "1", "ecs.ipv4Mask": mask,
                                                                        "ecs.ipv6Mask": mask}),
                                        "rows": {"upstreams": [self.UPSTREAM]}}])[0]
            self.assertEqual(messages, {}, mask)
            self.assertIsNone(blocky_validate(rendered(xml)[0]), mask)
        # a mask of -0 is no mask, as 0 is
        _, xml = run_model([{"fields": dict(self.DEFAULT, **{"ecs.ipv4Mask": "-0", "ecs.ipv6Mask": "-0"}),
                             "rows": {"upstreams": [self.UPSTREAM]}}])[0]
        self.assertNotIn("\necs:", rendered(xml)[0])

    def test_files_and_sockets_blocky_reads_as_root(self):
        lists = [{"enabled": "1", "group": "ads", "source": "/etc/master.passwd"}]
        self.assertIn("denylists.0.source", self.messages(denylists=lists))
        self.assertIn("hostsFile.sources", self.messages({"hostsFile.sources": "/etc/hosts,/etc/master.passwd"}))
        self.assertNotIn("hostsFile.sources", self.messages({"hostsFile.sources": "/etc/hosts"}))
        self.assertIn("bootstrap.0.content", self.messages(bootstrap=[{"enabled": "1", "type": "resolvfile",
                                                                       "content": "/etc/resolv.conf"}]))
        self.assertIn("redis.address", self.messages({"redis.address": "/var/run/configd.socket"}))
        self.assertNotIn("redis.address", self.messages({"redis.address": "/var/run/redis/redis.sock"}))
        self.assertIn("redis.sentinelAddresses", self.messages({"redis.address": "m", "redis.sentinelAddresses": "s:1,/x"}))
        self.assertIn("redis.password", self.messages({"redis.address": "r:6379", "redis.password": "file:/etc/master.passwd"}))
        # the server could read any file Blocky can, as root; PostgreSQL reads the files its options name
        for kind, target in (("mysql", "u:p@tcp(db)/b?allowAllFiles=true"), ("postgresql", "postgres://u@db/b?sslkey=/root/k.pem"),
                             ("timescale", "host=db sslrootcert=/etc/master.passwd")):
            self.assertIn("queryLog.target", self.messages({"queryLog.type": kind, "queryLog.target": target}), target)
        for target in ("postgres://u@db/b?sslmode=verify-full", "file:/usr/local/etc/blocky/secrets/db"):
            self.assertNotIn("queryLog.target", self.messages({"queryLog.type": "postgresql", "queryLog.target": target}), target)

    def test_an_upgrade_from_before_the_directories_switches_off_what_is_outside(self):
        """Values stored before 1.4_4, as the model then took them (M1_0_1, M1_0_3)."""
        messages, root = self.migrated(
            {"hostsFile.sources": "/etc/hosts,/etc/master.passwd", "redis.address": "/var/run/configd.socket",
             "redis.required": "1", "redis.password": "file:/etc/master.passwd", "queryLog.type": "dnstap",
             "queryLog.target": "unix:/var/run/configd.socket",
             "general.customZone": "$INCLUDE /etc/master.passwd\nnas.lan. 60 IN A 10.0.0.1",
             "redis.sentinelAddresses": "/tmp/s.sock, host2:26379, "},
            ("M1_0_1", "M1_0_3"),
            denylists=[{"enabled": "1", "group": "ads", "source": "/etc/master.passwd"},
                       {"enabled": "1", "group": "ads", "source": "https://example.com/ads.txt"}],
            bootstrap=[{"enabled": "1", "type": "resolvfile", "content": "/etc/resolv.conf"}])
        self.assertEqual(messages, {})
        self.assertEqual([row.findtext("enabled") for row in root.iter("denylists")], ["0", "1"])
        self.assertEqual(root.findtext(".//hostsFile/sources"), "/etc/hosts")
        self.assertEqual([row.findtext("enabled") for row in root.iter("bootstrap")
                          if row.find("type") is not None], ["0"])
        self.assertEqual((root.findtext(".//redis/address"), root.findtext(".//redis/required"),
                          root.findtext(".//redis/password")), ("", "0", ""))
        self.assertEqual(root.findtext(".//queryLog/type"), "none")
        self.assertEqual(root.findtext(".//general/customZone"), "nas.lan. 60 IN A 10.0.0.1")
        self.assertEqual(root.findtext(".//redis/sentinelAddresses"), "host2:26379")

    def test_the_last_default_upstream(self):
        found = self.messages(upstreams=[dict(self.UPSTREAM, group="lan")])
        self.assertIn("general.enabled", found)


@unittest.skipUnless(CORE and shutil.which("php"), "needs OPNSENSE_CORE and php")
class Import(unittest.TestCase):
    """importAction leaves out what the settings refuse, as core's importCsv() leaves out a refused record,
    and saves the rest."""

    BASE = "upstreams:\n  groups:\n    default: [1.1.1.1]\n"

    def left_out(self, left, label, message):
        self.assertTrue(any(line.startswith(label + ":") and message in line for line in left), (label, left))

    def test_what_the_settings_refuse_is_left_out(self):
        left, errors, xml = run_import([
            self.BASE + "blocking:\n  denylists:\n    ads: [/etc/master.passwd, https://example.com/ads.txt]\n"
            "bootstrapDns:\n  - resolvFile: /etc/resolv.conf\n  - upstream: 9.9.9.9\n"
            "hostsFile:\n  sources: [/etc/hosts, /etc/master.passwd]\n  hostsTTL: 2h\n"
            "redis:\n  address: /var/run/configd.socket\n  password: file:/etc/master.passwd\n  database: 2\n"])[0]
        self.assertEqual(errors, [])
        root = ET.fromstring(xml)
        self.assertEqual([row.findtext("source") for row in root.iter("denylists")], ["https://example.com/ads.txt"])
        self.assertEqual([row.findtext("content") for row in root.iter("bootstrap") if row.find("type") is not None],
                         ["9.9.9.9"])
        self.assertEqual((root.findtext(".//hostsFile/sources"), root.findtext(".//hostsFile/hostsTTL")), ("/etc/hosts", "2h"))
        self.assertEqual((root.findtext(".//redis/address") or "", root.findtext(".//redis/password") or "",
                          root.findtext(".//redis/database")), ("", "", "2"))
        self.left_out(left, "blocking.denylists.ads: /etc/master.passwd", "A file must be in /usr/local/etc/blocky/lists.")
        self.left_out(left, "bootstrapDns: /etc/resolv.conf", "A resolv file must be in /usr/local/etc/blocky/lists.")
        self.left_out(left, "hostsFile.sources: /etc/master.passwd", "A file must be /etc/hosts or in /usr/local/etc/blocky/lists.")
        self.left_out(left, "redis.address", "the Redis plugin socket")
        self.left_out(left, "redis.password", "A file: value must name a file in /usr/local/etc/blocky/secrets.")

    def test_a_refused_setting_goes_back_to_its_default(self):
        left, errors, xml = run_import([self.BASE + "blocking:\n  blockType: beef\n  blockTTL: 2m\n"])[0]
        self.assertEqual(errors, [])
        root = ET.fromstring(xml)
        self.assertEqual((root.findtext(".//general/blockType"), root.findtext(".//general/blockTTL")), ("zeroIP", "2m"))
        self.left_out(left, "blocking.blockType", "zeroIP")

    def test_a_setting_still_refused_at_its_default_takes_its_section(self):
        # without its target, a dnstap log is still refused, so query logging goes back to its defaults
        left, errors, xml = run_import([self.BASE + "queryLog:\n  type: dnstap\n  target: unix:/var/run/configd.socket\n"])[0]
        self.assertEqual(errors, [])
        root = ET.fromstring(xml)
        self.assertEqual((root.findtext(".//queryLog/type"), root.findtext(".//queryLog/target") or ""), ("none", ""))
        self.left_out(left, "queryLog.target", "tcp://host:port")
        self.left_out(left, "queryLog", "tcp://host:port")

    def test_a_list_keeps_the_entries_the_settings_take(self):
        left, errors, xml = run_import([
            self.BASE + "hostsFile:\n  sources: [/etc/hosts, /etc/blocky/hosts.local, https://example.com/h.txt]\n"
            "redis:\n  address: r:6379\n  sentinelAddresses: [s1:26379, /tmp/x.sock, s2:26379]\n"])[0]
        self.assertEqual(errors, [])
        root = ET.fromstring(xml)
        self.assertEqual(root.findtext(".//hostsFile/sources"), "/etc/hosts,https://example.com/h.txt")
        self.assertEqual(root.findtext(".//redis/sentinelAddresses"), "s1:26379,s2:26379")
        self.left_out(left, "hostsFile.sources: /etc/blocky/hosts.local", "A file must be /etc/hosts or in")
        self.left_out(left, "redis.sentinelAddresses: /tmp/x.sock", "not Unix sockets")

    def test_a_group_left_without_lists_keeps_its_references(self):
        # the kids list is a file the settings refuse, so kids has no list, which Blocky logs and runs with
        left, errors, xml = run_import([
            self.BASE + "blocking:\n  denylists:\n    ads: [https://example.com/ads.txt]\n    kids: [/etc/blocky/kids.txt]\n"
            "  clientGroupsBlock:\n    default: [ads, kids]\n    10.0.0.5: [kids]\n"
            "  schedules:\n    evenings:\n      weekdays: [mon]\n  listSchedules:\n    ads: [evenings]\n    kids: [evenings]\n"])[0]
        self.assertEqual(errors, [])
        root = ET.fromstring(xml)
        self.assertEqual([row.findtext("group") for row in root.iter("denylists") if row.find("group") is not None], ["ads"])
        self.assertEqual([(row.findtext("client"), row.findtext("groups")) for row in root.iter("clientgroups")],
                         [("default", "ads,kids"), ("10.0.0.5", "kids")])
        self.assertEqual([(row.findtext("name"), row.findtext("groups")) for row in root.iter("schedules")
                          if row.find("name") is not None], [("evenings", "ads,kids")])
        self.left_out(left, "blocking.denylists.kids", "/usr/local/etc/blocky/lists")

    def test_negative_durations_as_the_template_writes_them(self):
        fields = {"general.cacheMinTime": "-1", "general.cacheMaxTime": "-5", "general.cacheTimeNegative": "-1",
                  "general.downloadReadHeaderTimeout": "-1"}
        _, xml = run_model([{"fields": dict(fields, **{"general.enabled": "1"}),
                             "rows": {"upstreams": [{"enabled": "1", "group": "default", "server": "1.1.1.1"}]}}])[0]
        text, _ = rendered(xml)
        left, errors, xml = run_import([text])[0]
        self.assertEqual((left, errors), ([], []))
        root = ET.fromstring(xml)
        self.assertEqual([root.findtext(".//general/" + ref.split(".")[1]) for ref in fields], ["-1m", "-5m", "-1m", "-1m"])

    def test_of_keys_blocky_reads_as_one_the_first_stays(self):
        left, errors, xml = run_import([self.BASE + "customDNS:\n  rewrite:\n    Fritz.Box: fritz.lan\n    fritz.box.: other.lan\n"
                                        "    nas.lan: n.lan\n"])[0]
        self.assertEqual(errors, [])
        root = ET.fromstring(xml)
        self.assertEqual([(row.findtext("fromDomain"), row.findtext("toDomain")) for row in root.iter("customdnsrewrite")],
                         [("Fritz.Box", "fritz.lan"), ("nas.lan", "n.lan")])
        self.left_out(left, "customDNS.rewrite.fritz.box.", "Another enabled entry already uses this")

    @unittest.skipUnless(BLOCKY, "needs blocky")
    def test_control_characters_are_left_out_before_apply(self):
        left, errors, xml = run_import(['upstreams:\n  userAgent: "a\\x7fb"\n  groups:\n    default: [1.1.1.1, "9.9.9\\x85.9"]\n'
                                        'blocking:\n  denylists:\n    ads: [https://example.com/ads.txt]\n'
                                        '  clientGroupsBlock:\n    "laptop\\x9f": [ads]\n    default: [ads]\n'])[0]
        self.assertEqual(errors, [])
        root = ET.fromstring(xml)
        self.assertEqual(root.findtext(".//general/userAgent") or "", "")
        self.assertEqual([row.findtext("server") for row in root.iter("upstreams") if row.find("server") is not None], ["1.1.1.1"])
        self.assertEqual([row.findtext("client") for row in root.iter("clientgroups")], ["default"])
        self.left_out(left, "upstreams.userAgent", "Enter text without control characters.")
        self.assertIsNone(blocky_validate(rendered(xml)[0]), "Apply takes what was saved")

    def test_what_leaving_out_cannot_answer_saves_nothing(self):
        left, errors, xml = run_import(["upstreams:\n  groups:\n    lan: [1.1.1.1]\n"])[0]
        self.assertIsNone(xml)
        self.assertTrue(any(line.startswith("general.enabled:") for line in errors), errors)

    def test_a_config_blocky_runs_imports(self):
        """Whatever the settings leave out, an import of a file Blocky runs saves."""
        for text in ("upstreams:\n  groups:\n    default: [1.1.1.1]\ncustomDNS:\n  rewrite:\n    Fritz.Box: fritz.lan\n"
                     "    fritz.box: other.lan\n    fritz.box.: third.lan\n",
                     "upstreams:\n  groups:\n    default: [1.1.1.1]\nblocking:\n  denylists:\n"
                     "    ads: [https://example.com/ads.txt]\n  clientGroupsBlock:\n    default: [ads]\n  schedules:\n"
                     "    never:\n      weekdays: [mon]\n      start: '00:00'\n      end: '00:00'\n"
                     "  listSchedules:\n    ads: [never]\n",
                     "upstreams:\n  groups:\n    default: [1.1.1.1]\nblocking:\n  denylists:\n    ads: [ads.example.com]\n"
                     "    kids: [https://example.com/k.txt]\n  clientGroupsBlock:\n    default: [ads, kids]\n"
                     "    10.0.0.5: [ads]\n  schedules:\n    work:\n      weekdays: [mon]\n  listSchedules:\n    ads: [work]\n",
                     'upstreams:\n  groups:\n    default: [1.1.1.1]\nredis:\n  address: "r:6379\\r"\n  password: "pa\\nss"\n'
                     'hostsFile:\n  sources:\n    - "/usr/local/etc/blocky/lists/a\\x01b"\n'
                     'blocking:\n  denylists:\n    ads: ["a\\x7fb.com\\nads.example.com\\n"]\n'
                     'queryLog:\n  type: mysql\n  target: "u:p@tcp(db)/b\\n"\n'):
            if BLOCKY:
                self.assertIsNone(blocky_validate(text), text)
            _, errors, xml = run_import([text])[0]
            self.assertEqual(errors, [], text)
            self.assertIsNotNone(xml, text)


if __name__ == "__main__":
    unittest.main()
