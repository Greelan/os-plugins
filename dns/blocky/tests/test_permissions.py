"""Who may do what: changes are POST-only, a read-only user cannot start an import, and the configd
actions that stop Blocky or read a caller's file take calls from root and the web interface only."""

import configparser
import os
import re
import unittest
import xml.etree.ElementTree as ET

SRC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src", "opnsense")
API = os.path.join(SRC, "mvc", "app", "controllers", "OPNsense", "Blocky", "Api")
ACTIONS = os.path.join(SRC, "service", "conf", "actions.d", "actions_blocky.conf")
ACL = os.path.join(SRC, "mvc", "app", "models", "OPNsense", "Blocky", "ACL", "ACL.xml")
# core's helpers that refuse anything but POST themselves
POST_HELPERS = ("setBase(", "addBase(", "delBase(", "toggleBase(")
READS = re.compile(r"^(search|get)[A-Z]|^secrets$")


# a method's signature: parameters may hold defaults such as array(), and a return type may follow
SIGNATURE = re.compile(r"\bfunction (\w+)\((?:[^()]|\([^()]*\))*\)\s*(?::\s*\??[\w\\|]+\s*)?\{")


def methods(path):
    """{name: body} of a controller's methods, each with the bodies of the methods it calls."""
    with open(path) as handle:
        text = handle.read()
    found = list(SIGNATURE.finditer(text))
    # every method is read, or a guard could go unchecked
    assert len(found) == len(re.findall(r"\bfunction \w+\(", text)), path
    bodies = {}
    for match in found:
        depth, end = 1, match.end()
        while depth:
            depth += {"{": 1, "}": -1}.get(text[end], 0)
            end += 1
        bodies[match.group(1)] = text[match.end():end]
    return {name: body + "".join(bodies.get(called, "") for called in re.findall(r"\$this->(\w+)\(", body))
            for name, body in bodies.items()}


def actions():
    for name in sorted(os.listdir(API)):
        for method, body in methods(os.path.join(API, name)).items():
            if method.endswith("Action"):
                yield f"{name}:{method}", method[:-len("Action")], body


class Permissions(unittest.TestCase):
    def test_changes_are_post_only(self):
        for where, action, body in actions():
            if not READS.search(action):
                self.assertTrue("isPost()" in body or any(h in body for h in POST_HELPERS), where)

    def test_a_read_only_user_is_refused_before_the_import_is_parsed(self):
        body = methods(os.path.join(API, "SettingsController.php"))["importAction"]
        self.assertLess(body.index("throwReadOnly()"), body.index("configdpRun("))

    def test_configd_actions_that_stop_or_take_a_file(self):
        conf = configparser.ConfigParser(interpolation=None)
        conf.read(ACTIONS)
        for name in conf.sections():
            action = conf[name]
            if "%s" in action.get("parameters", "") or re.search(r"\bstop\b", action["command"]):
                self.assertEqual(action.get("allowed_groups"), "wheel,wwwonly", name)

    def test_acl_covers_the_pages_and_the_api(self):
        patterns = {p.text for p in ET.parse(ACL).getroot().iter("pattern")}
        self.assertLessEqual({"ui/blocky/*", "api/blocky/*"}, patterns)


if __name__ == "__main__":
    unittest.main()
