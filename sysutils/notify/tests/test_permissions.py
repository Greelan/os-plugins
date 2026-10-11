"""Who may do what: changes are POST-only, sending, building and reading channels or summaries
need a full administrator, and the configd actions that send, delete or read a caller's file take
calls from root and the web interface only."""

import configparser
import os
import re
import unittest
import xml.etree.ElementTree as ET

SRC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src", "opnsense")
CONTROLLERS = os.path.join(SRC, "mvc", "app", "controllers", "OPNsense", "Notify")
API = os.path.join(CONTROLLERS, "Api")
ACTIONS = os.path.join(SRC, "service", "conf", "actions.d", "actions_notify.conf")
ACL = os.path.join(SRC, "mvc", "app", "models", "OPNsense", "Notify", "ACL", "ACL.xml")
# core's helpers that refuse anything but POST themselves
POST_HELPERS = ("setBase(", "addBase(", "delBase(", "toggleBase(")
READS = re.compile(r"^(search|get)[A-Z]|^(services|status)$")
# open to the page's privilege: the Apprise service list, cron, and a channel's fields without secrets
NOT_ADMIN = {"services", "reconfigure", "searchChannel", "getChannel", "delChannel", "toggleChannel"}
# configd reads any local user may run, as core leaves its own reads open
OPEN_READS = {"report", "describe"}


def methods(path):
    """{name: body} of a controller's methods, each with the bodies of the methods it calls."""
    with open(path) as handle:
        text = handle.read()
    bodies = {}
    for match in re.finditer(r"function (\w+)\([^)]*\)\s*\{", text):
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

    def test_a_full_administrator_before_the_backend(self):
        with open(os.path.join(API, "SettingsController.php")) as handle:
            self.assertIn("$internalSaveRequiresAdmin = true;", handle.read())
        for where, action, body in actions():
            if action not in NOT_ADMIN:
                self.assertIn("throwNotFullAdmin()", body, where)
                backend = re.search(r"configdp?Run\(", body)
                if backend:
                    self.assertLess(body.index("throwNotFullAdmin()"), backend.start(), where)
        view = methods(os.path.join(CONTROLLERS, "ReportController.php"))["viewAction"]
        self.assertLess(view.index("'page-all'"), view.index("configdpRun("))

    def test_configd_actions_that_send_delete_or_take_a_file(self):
        conf = configparser.ConfigParser(interpolation=None)
        conf.read(ACTIONS)
        for name in conf.sections():
            if "%s" in conf[name].get("parameters", "") and name not in OPEN_READS:
                self.assertEqual(conf[name].get("allowed_groups"), "wheel,wwwonly", name)
        self.assertLessEqual({"test", "summary", "delete", "build", "parse"},
                             {n for n in conf.sections() if conf[n].get("allowed_groups")})

    def test_acl_covers_the_pages_and_the_api(self):
        patterns = {p.text for p in ET.parse(ACL).getroot().iter("pattern")}
        self.assertLessEqual({"ui/notify/*", "api/notify/*"}, patterns)


if __name__ == "__main__":
    unittest.main()
