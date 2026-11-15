**Checklist**

- [ ] For a non-trivial change, I opened an issue first and linked it below.
- [ ] The change covers one plugin, and the commit subject starts with its path, e.g. `sysutils/notify: ...`.
- [ ] A change to what the package installs bumps `PLUGIN_REVISION` (a fix) or `PLUGIN_VERSION` (a feature) in the plugin's `Makefile`, and adds a line to its `CHANGELOG.md` that says what changes for the user.
- [ ] `python3 tools/vendor.py update`, then `OPNSENSE_CORE=/path/to/opnsense/core sh tools/run-tests.sh` passes.
- [ ] I tested the change on OPNsense (version: ).

---

**Describe the problem**

What this pull request addresses.

---

**Describe the proposed solution**

What this pull request changes, and why.

---

**Related issue**

Fixes #
