"""Whatever the model accepts, Blocky accepts: values are swept through every field, the model
decides which it takes, core's template engine renders those, and `blocky validate` checks each.

Needs OPNSENSE_CORE, php and a blocky binary (BLOCKY, or blocky on PATH) of the pinned version."""

import concurrent.futures
import hashlib
import json
import os
import random
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
    "  IN A 10.0.0.1\nhost IN A 10.0.0.2", "$TTL 3600\n@ IN A 10.0.0.1",
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

# zones on both sides of each rule Blocky's parser (miekg/dns, no origin) applies
ZONES = [
    "host IN A 10.0.0.1",
    "host A 10.0.0.1",
    "host 300 IN A 10.0.0.1",
    "host IN 300 A 10.0.0.1",
    "host 1h A 10.0.0.1",
    "host 1W2D A 10.0.0.1",
    "host a 10.0.0.1",
    "host in a 10.0.0.1",
    "  IN A 10.0.0.1",
    "host IN A 10.0.0.1\n  IN A 10.0.0.2",
    "@ IN A 10.0.0.1",
    "$TTL 3600\nhost IN A 10.0.0.1",
    "$ORIGIN lan.\nhost IN A 10.0.0.1",
    "$ORIGIN lan\nhost A 1.1.1.1",
    "$TTL\nhost A 1.1.1.1",
    "$TTL abc\nhost A 1.1.1.1",
    "$GENERATE 1-2 host$ A 10.0.0.$",
    "$FOO bar",
    "host IN A 10.0.0.256",
    "host IN A ::1",
    "host IN AAAA ::1",
    "host IN AAAA 10.0.0.1",
    "host IN A",
    "host IN CNAME other",
    "host IN CNAME other.lan.",
    "host IN CNAME bad name",
    "host IN MX 10 mail",
    "host IN MX mail",
    "host IN TXT \"hello world\"",
    "host IN TXT hello",
    "host IN TXT \"unterminated",
    "host IN SRV 0 5 5060 sip",
    "host IN SRV 0 5 sip",
    "host IN PTR x.lan.",
    "host IN NS ns1",
    "host IN HTTPS 1 . alpn=h2",
    "host IN CAA 0 issue \"x\"",
    "host IN FOO 1.2.3.4",
    "host IN A 10.0.0.1 ; comment",
    "; only comment",
    "host IN A ( 10.0.0.1 )",
    "host IN SOA ns admin ( 1 2 3 4 5 )",
    "host IN SOA ns admin ( 1 2 3 4 5",
    "*.lan IN A 10.0.0.1",
    "host.lan. IN A 10.0.0.1",
    "ho st IN A 1.1.1.1",
    "host IN A 1.1.1.1 extra",
    "host IN CH A 1.1.1.1",
    "host CH A 1.1.1.1",
    "host CLASS1 A 1.1.1.1",
    "host TYPE1 1.1.1.1",
    "host IN TYPE1 \\# 4 0a000001",
    "host 2147483648 A 1.1.1.1",
    "host 4294967296 A 1.1.1.1",
    "10",
    "example.com",
    "a b",
    "host IN A 1.1.1.1\n\n\nh2 IN A 1.1.1.2",
    "\thost IN A 1.1.1.1",
    "host\tIN\tA\t1.1.1.1",
    "host IN MX 70000 mail",
    "host IN A 01.1.1.1",
    "host IN AAAA fe80::1%em0",
    "host IN CNAME .",
    "host IN SRV 0 5 70000 sip",
    "host IN A 1.1.1.1\r\nh2 IN A 1.1.1.2",
    "host IN TXT \"a\" \"b\"",
    "host IN TXT \"a\\\"b\"",
    "host IN A 1.1.1.1 )",
    "host IN NS ns1 ; c\n  IN NS ns2",
    "$ORIGIN .\nhost A 1.1.1.1",
    "@ A 1.1.1.1\n$ORIGIN x.\n@ A 1.1.1.2",
    "h.lan. IN A 10.0.0.1",
    "h.lan. A 10.0.0.1",
    "h.lan. 300 IN A 10.0.0.1",
    "h.lan. IN 300 A 10.0.0.1",
    "h.lan. 1h A 10.0.0.1",
    "h.lan. 1W2D A 10.0.0.1",
    "h.lan. a 10.0.0.1",
    "h.lan. in a 10.0.0.1",
    "h.lan. IN A 10.0.0.1\n  IN A 10.0.0.2",
    "$TTL 3600\nh.lan. A 10.0.0.1",
    "$TTL 1h\nh.lan. A 10.0.0.1",
    "$TTL\nh.lan. A 1.1.1.1",
    "$GENERATE 1-2 h$.lan. A 10.0.0.$",
    "$ORIGIN lan.\n@ A 1.1.1.1",
    "$ORIGIN lan.\nh A 1.1.1.1\n$ORIGIN x.\nh A 1.1.1.2",
    "$origin lan.\nh A 1.1.1.1",
    "$ttl 60\nh.lan. A 1.1.1.1",
    "h.lan. IN A 10.0.0.256",
    "h.lan. IN A ::1",
    "h.lan. IN AAAA ::1",
    "h.lan. IN AAAA 10.0.0.1",
    "h.lan. IN A",
    "h.lan. IN",
    "h.lan. IN CNAME other",
    "h.lan. IN CNAME other.lan.",
    "h.lan. IN CNAME bad name",
    "h.lan. IN MX 10 mail.lan.",
    "h.lan. IN MX mail.lan.",
    "h.lan. IN TXT \"hello world\"",
    "h.lan. IN TXT hello",
    "h.lan. IN TXT \"unterminated",
    "h.lan. IN SRV 0 5 5060 sip.lan.",
    "h.lan. IN SRV 0 5 sip.lan.",
    "h.lan. IN PTR x.lan.",
    "h.lan. IN NS ns1.lan.",
    "h.lan. IN HTTPS 1 . alpn=h2",
    "h.lan. IN CAA 0 issue \"x\"",
    "h.lan. IN FOO 1.2.3.4",
    "h.lan. IN A 10.0.0.1 ; comment",
    "h.lan. IN A ( 10.0.0.1 )",
    "h.lan. IN A (\n 10.0.0.1 )",
    "h.lan. IN SOA ns.lan. admin.lan. ( 1 2 3 4 5 )",
    "h.lan. IN SOA ns.lan. admin.lan. ( 1 2 3 4 5",
    "*.lan. IN A 10.0.0.1",
    "h.lan. IN A 1.1.1.1 extra",
    "h.lan. IN CH A 1.1.1.1",
    "h.lan. CH A 1.1.1.1",
    "h.lan. CLASS1 A 1.1.1.1",
    "h.lan. TYPE1 1.1.1.1",
    "h.lan. IN TYPE1 \\# 4 0a000001",
    "h.lan. 2147483648 A 1.1.1.1",
    "h.lan. 4294967296 A 1.1.1.1",
    "\th.lan. IN A 1.1.1.1",
    "h.lan.\tIN\tA\t1.1.1.1",
    "h.lan. IN MX 70000 mail.lan.",
    "h.lan. IN A 01.1.1.1",
    "h.lan. IN AAAA fe80::1%em0",
    "h.lan. IN CNAME .",
    "h.lan. IN SRV 0 5 70000 sip.lan.",
    "h.lan. IN TXT \"a\" \"b\"",
    "h.lan. IN A 1.1.1.1 )",
    "h.lan. IN NS ns1.lan. ; c\n  IN NS ns2.lan.",
    "h..lan. A 1.1.1.1",
    "h_x.lan. A 1.1.1.1",
    "h.lan. A 1.1.1",
    "h.lan. IN A 1.1.1.1\nh.lan. A 1.1.1.2",
    "h.lan. 60 A 1.1.1.1\nx.lan. A 1.1.1.2",
    "h.lan. IN A 1.1.1.1\n  1.1.1.2",
    "h.lan. IN A 1.1.1.1 ; x (",
    "h.lan. IN TXT \"a;b\"",
    "h.lan. IN TXT \"a(b\"",
    "h.lan. IN MX 10 mail",
    "h.lan. IN AAAA ::ffff:1.2.3.4",
    "h.lan. IN A 1.1.1.1\\",
    "\\@.lan. A 1.1.1.1",
    "h.lan. IN DS 1 2 3 ABCD",
    "h.lan. IN OPT 1",
    "h.lan. IN ANY 1.1.1.1",
    "h.lan. IN SPF \"v=spf1\"",
    "h.lan. IN NULL",
    "h.lan. IN A 1.1.1.1 1.1.1.2",
]

# enough values from each sweep to build rich baselines and random combinations from
SEED = 20260925
RANDOM_CASES = 400


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
    if len(cases) > 500:
        return [r for i in range(0, len(cases), 500) for r in run_model(cases[i:i + 500])]
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as handle:
        json.dump(cases, handle)
    try:
        run = subprocess.run(["php", os.path.join(HERE, "model_harness.php"), handle.name],
                             capture_output=True, text=True)
    finally:
        os.unlink(handle.name)
    out = run.stdout
    assert run.returncode == 0, (run.stdout + run.stderr)[-2000:]
    results = [json.loads(line) for line in out.splitlines() if line.startswith("{")]
    assert len(results) == len(cases), out[-2000:]
    return [({field: text for field, text in r["messages"]}, r["xml"]) for r in results]


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
        with open(os.path.join(self.target, "usr", "local", "etc", "blocky", "config.yml")) as handle:
            return handle.read()


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
             if line.strip() and "Validating configuration file" not in line]
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

        # a minimal accepted row per array: each field takes the first value the model takes there
        row_base = {}
        for name, fields in arrays.items():
            row = {"enabled": "1"}
            for field, node in fields:
                if field == "enabled":
                    continue
                values = candidates(node)
                verdicts = run_model([case(rows={name: [dict(row, **{field: v})]}) for v in values])
                index = len(base["rows"].get(name, []))
                taken = [v for v, (msgs, _) in zip(values, verdicts)
                         if f"{name}.{index}.{field}" not in msgs and v != ""]
                if taken:
                    row[field] = taken[0]
            row_base[name] = row

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

        first = sweep(base)
        verdicts = dict(zip(first, run_model(list(first.values()))))
        taken = {}
        for (where, value), (_, xml) in verdicts.items():
            if xml is not None:
                taken.setdefault(where, []).append(value)

        # a rich baseline: one of every row, then each field on something other than its default
        rich = case(rows={name: [row] for name, row in row_base.items()})
        for ref, node in scalars.items():
            default = node.findtext("Default") or ""
            for value in [v for v in taken.get(ref, []) if v not in ("", default)][:3]:
                trial = case({ref: value}, start=rich)
                if run_model([trial])[0][1] is not None:
                    rich = trial
                    break

        cases = list(first.items())
        cases += list(sweep(rich).items())
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

        results = run_model([c for _, c in cases])
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp)
        renderer = Renderer(tmp)
        configs, failures = {}, {}
        for ((where, value), _), (_, xml) in zip(cases, results):
            if xml is None:
                continue
            try:
                text = renderer.render(xml)
            except Exception as error:  # a template that does not render is a failure too
                failures.setdefault(where, []).append((value, f"render: {error}"))
                continue
            configs.setdefault(hashlib.sha256(text.encode()).hexdigest(), (text, where, value))

        valid = []
        with concurrent.futures.ThreadPoolExecutor(8) as pool:
            reasons = pool.map(lambda item: blocky_validate(item[0]), configs.values())
            for (text, where, value), reason in zip(configs.values(), reasons):
                if reason is not None:
                    failures.setdefault(where, []).append((value, reason))
                else:
                    valid.append((text, where, value))

        # a config Blocky runs must import: the importer's output, applied as importAction does
        sys.path[:0] = [SCRIPTS, os.path.join(SCRIPTS, "lib")]
        import yaml
        from import_config import Mapper
        imports = []
        for text, _, _ in valid:
            mapped = Mapper(yaml.safe_load(text)).run()
            imports.append({"fields": dict({f"{section}.{field}": v for section, fields in mapped["scalars"].items()
                                            for field, v in fields.items()}, **{"general.enabled": "1"}),
                            "rows": mapped["arrays"]})
        for (_, where, value), (messages, _) in zip(valid, run_model(imports)):
            for field, text in messages.items():
                failures.setdefault(f"import {where}", []).append((value, f"{field}: {text}"))

        report = "\n".join(f"{where}: {len(found)} value(s), e.g.\n" + "\n".join(
            f"    {value!r}: {reason}" for value, reason in found[:3]) for where, found in failures.items())
        self.assertFalse(failures, f"Blocky rejects settings the model accepts in {len(failures)} field(s) "
                                   f"({len(configs)} distinct configs checked):\n{report}")

    def test_zone_check_matches_blocky(self):
        """Stricter than Blocky refuses a working config on import; looser lets Blocky fail to start."""
        results = run_model([{"fields": {"general.customZone": zone}, "rows": {}} for zone in ZONES])
        mismatches = []
        for zone, (messages, _) in zip(ZONES, results):
            text = ("upstreams:\n  groups:\n    default: [1.1.1.1]\ncustomDNS:\n  zone: |2\n" +
                    "".join("    " + line + "\n" for line in zone.replace("\r", "").split("\n")))
            blocky = blocky_validate(text)
            model = messages.get("general.customZone")
            if (blocky is None) != (model is None):
                mismatches.append(f"{zone!r}: blocky {blocky or 'accepts'}; model {model or 'accepts'}")
        self.assertFalse(mismatches, "\n".join(mismatches))


if __name__ == "__main__":
    unittest.main()
