"""A URL Apprise accepts for each of its services, built from Apprise itself: the templates and token
rules its details() declares, and the patterns each plugin checks its input with in its own code.
For tests that have to reach every service, not only those a person wrote a URL for."""

import inspect
import itertools
import re
import urllib.parse

try:
    from re import _constants as sre_constants
    from re import _parser as sre_parse
except ImportError:  # before Python 3.11
    import sre_constants  # type: ignore[no-redef]
    import sre_parse  # type: ignore[no-redef]

# forms a token with no declared rule often wants, tried until Apprise accepts one
CANDIDATES = ["user@example.com", "+15551234567", "15551234567", "N0CALL", "N0CALL-9", "*ABCDEFG", "ABCDEFGH",
              "abc", "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d", "12345", "channel", "#general", "user",
              "abcdef0123456789abcdef0123456789"]


def from_regex(pattern):
    """A short string the pattern matches, or None."""
    def pick(ranges):
        if any(op is sre_constants.NEGATE for op, _ in ranges):
            return "a"
        for op, arg in ranges:
            if op is sre_constants.LITERAL:
                return chr(arg)
            if op is sre_constants.RANGE:
                return next((c for c in "a0A" if arg[0] <= ord(c) <= arg[1]), chr(arg[0]))
            if op is sre_constants.CATEGORY:
                return {"CATEGORY_DIGIT": "1", "CATEGORY_SPACE": " "}.get(str(arg), "a")
        return "a"

    def walk(items):
        out = []
        for op, arg in items:
            if op is sre_constants.LITERAL:
                out.append(chr(arg))
            elif op is sre_constants.ANY:
                out.append("a")
            elif op is sre_constants.IN:
                out.append(pick(arg))
            elif op in (sre_constants.MAX_REPEAT, sre_constants.MIN_REPEAT):
                out.append(walk(arg[2]) * max(arg[0], 1))
            elif op is sre_constants.SUBPATTERN:
                out.append(walk(arg[-1]))
            elif op is sre_constants.BRANCH:
                out.append(walk(arg[1][0]))
        return "".join(out)

    try:
        return walk(sre_parse.parse(pattern))
    except Exception:
        return None


def compiled(rule):
    flags = re.I if "i" in ((rule[1] if len(rule) > 1 else "") or "") else 0
    try:
        return re.compile(rule[0], flags)
    except re.error:
        return None


def token_values(key, token):
    """Values to try for a token: fixed ones for the usual parts, else realistic ones its rule takes,
    then one derived from the rule itself."""
    fixed = {"port": ["8080"], "user": ["user"], "botname": ["user"], "password": ["pass", "12345"]}
    if key in fixed:
        return fixed[key]
    rule = token.get("regex") or [None]
    if key == "host":
        return [from_regex(rule[0])] if rule[0] else ["example.com"]
    kind = str(token.get("type", "string"))
    if kind.startswith("int"):
        low = token.get("min")
        return [str(low if low is not None and low > 0 else 1)]
    if kind.startswith("choice"):
        return [str(token.get("default") or token["values"][0])]
    if not rule[0]:
        return CANDIDATES
    pattern = compiled(rule)
    sample = from_regex(rule[0])
    return [c for c in CANDIDATES if pattern is None or pattern.match(c)] + ([sample] if sample else [])


def code_samples(plugin):
    """Values from the patterns a plugin checks its input with, which details() does not always
    declare, e.g. PagerTree's int_ integration IDs."""
    try:
        source = inspect.getsource(inspect.getmodule(plugin))
    except (OSError, TypeError):
        return []
    found = []
    for pattern in re.findall(r'(?:validate_regex\(\s*[^,]+,\s*|re\.compile\(\s*)r?"((?:[^"\\]|\\.)+)"', source):
        sample = from_regex(pattern)
        if sample and sample not in found:
            found.append(sample)
    return found


def build(entry, instantiate):
    """A URL for a service Apprise builds a plugin from, or None."""
    from apprise.plugins import N_MGR
    tokens = entry["details"]["tokens"]
    schemas = list(entry.get("secure_protocols") or []) + list(entry.get("protocols") or [])
    known = [s for s in schemas if s in N_MGR]
    extra = code_samples(N_MGR[known[0]]) if known else []
    for template in entry["details"]["templates"]:
        keys = [k for k in re.findall(r"{(\w+)}", template) if k != "schema"]
        if any(k not in tokens for k in keys):
            continue
        options = [token_values(k, tokens[k]) + ([] if k in ("host", "port", "user", "password") else extra)
                   for k in keys]
        for values in itertools.islice(itertools.product(*options), 3000):
            url = template
            for key, value in zip(keys, values):
                url = url.replace("{" + key + "}", urllib.parse.quote(value, safe=":@+#"))
            for schema in schemas:
                if instantiate(url.replace("{schema}", schema)) is not None:
                    return url.replace("{schema}", schema)
    return None
