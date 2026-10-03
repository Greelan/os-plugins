#!/usr/bin/env python3
# Render the pkg.greelan.net site into repo/: index.html from README.md (with a
# per-plugin "changelog" link injected into each plugin heading), one
# changelog/<pkgname>.html per plugin from its CHANGELOG.md, and a directory
# listing per package folder (files/index.html for the root, index.html below it).
import datetime
import glob
import html
import os
import re
from urllib.parse import quote

import markdown

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPO = os.path.join(ROOT, "repo")
os.makedirs(os.path.join(REPO, "changelog"), exist_ok=True)

HEAD, FOOT = open(os.path.join(ROOT, "tools", "index.html")).read().split("%%CONTENT%%")
TITLE = "Greelan's plugin repository"
BUILT = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")


def render(md):
    # toc adds heading ids, which the stylesheet's scroll offsets rely on
    body = markdown.markdown(md, extensions=["fenced_code", "tables", "toc"])
    # external links open in a new tab
    return re.sub(r'<a href="(https?://)', r'<a target="_blank" rel="noopener noreferrer" href="\1', body)


def page(body, title=None, built=False):
    # the build date only on the landing page
    footer = f"<footer>\n  <div>Last built {BUILT}</div>\n</footer>" if built else ""
    return (HEAD.replace("%%TITLE%%", html.escape(title or TITLE))
            + body
            + FOOT.replace("%%FOOTER%%", footer))


def built_packages():
    """name -> {version: [abi, ...]} for everything in the built repository."""
    found = {}
    for abi_dir in sorted(glob.glob(os.path.join(REPO, "*"))):
        abi = os.path.basename(abi_dir)
        if not os.path.isdir(abi_dir) or abi == "changelog":
            continue
        for pkg in glob.glob(os.path.join(abi_dir, "*.pkg")):
            name, _, version = os.path.basename(pkg)[:-len(".pkg")].rpartition("-")
            if name:
                found.setdefault(name, {}).setdefault(version, []).append(abi)
    return found


def package_list(names, found):
    """Versions and architectures built for these package names."""
    items = []
    for name in names:
        for version, abis in sorted(found.get(name, {}).items()):
            items.append('<li><code>{}</code> {} <span class="abi">{}</span></li>'.format(
                html.escape(name), html.escape(version), html.escape(", ".join(sorted(abis)))))
    return '<ul class="pkgs">\n%s\n</ul>' % "\n".join(items) if items else ""


def bundled_version(mk, name):
    """Version of the engine a plugin bundles, from its lib/VENDOR pins."""
    pattern = os.path.join(os.path.dirname(mk), "src", "opnsense", "scripts", "*", "*", "lib", "VENDOR")
    for manifest in glob.glob(pattern):
        for line in open(manifest):
            fields = line.split()
            if len(fields) > 1 and not line.startswith("#") and fields[0].lower() == name.lower():
                return fields[1]
    return ""


def makefile_field(path, key):
    m = re.search(rf"^{key}=\s*(.*)$", open(path).read(), re.M)
    return m.group(1).strip() if m else ""


# plugins keyed by package name (os-<PLUGIN_NAME>), with changelog and dependencies
plugins = []
for mk in sorted(glob.glob(os.path.join(ROOT, "*", "*", "Makefile"))):
    if "Mk/plugins.mk" not in open(mk).read():
        continue
    name = makefile_field(mk, "PLUGIN_NAME")
    if not name:
        continue
    changelog = os.path.join(os.path.dirname(mk), "CHANGELOG.md")
    bundled = makefile_field(mk, "PLUGIN_BUNDLED")
    plugins.append((
        f"os-{name}",
        changelog if os.path.isfile(changelog) else None,
        makefile_field(mk, "PLUGIN_DEPENDS").split(),
        (bundled, bundled_version(mk, bundled)) if bundled else None,
    ))

# landing page: README, with a changelog link and the built packages under each
# plugin heading (which carries a toc id, so match attributes too)
found = built_packages()
listed = set()
body = render(open(os.path.join(ROOT, "README.md")).read())
for pkgname, changelog, depends, bundled in plugins:
    pattern = r"<h3([^>]*)>%s</h3>" % re.escape(pkgname)
    link = (f' <a class="cl-link" href="changelog/{pkgname}.html">changelog &raquo;</a>'
            if changelog else "")
    names = [pkgname] + depends
    listed.update(names)
    packages = package_list(names, found)
    if bundled and bundled[1]:
        # vendored into the plugin package rather than installed beside it
        packages = packages.replace('</ul>', '<li><code>{}</code> {} <span class="abi">{}</span></li>\n</ul>'.format(
            html.escape(bundled[0]), html.escape(bundled[1]), "bundled"))
    body, injected = re.subn(
        pattern, lambda m: f'<h3{m.group(1)} class="plugin">{pkgname}{link}</h3>\n{packages}', body)
    if not injected:
        raise SystemExit(f"no <h3>{pkgname}</h3> heading in README.md to list packages under")

# anything belonging to no plugin, so nothing ships unannounced
leftovers = package_list(sorted(set(found) - listed), found)
if leftovers:
    body += f'<h2 id="other-packages">Other packages</h2>\n{leftovers}'
open(os.path.join(REPO, "index.html"), "w").write(page(body, built=True))

# one changelog page per plugin that ships one (drop the file's title, keep "## version" as h2)
for pkgname, changelog, _, _ in plugins:
    if not changelog:
        continue
    text = open(changelog).read()
    m = re.search(r"^## ", text, re.M)
    content = text[m.start():] if m else text
    body = f'<h1 id="{pkgname}"><span class="plugin">{pkgname}</span> changelog</h1>\n' + render(content)
    out = os.path.join(REPO, "changelog", f"{pkgname}.html")
    open(out, "w").write(page(body, title=f"{pkgname} changelog"))


# site pages rather than repository content
UNLISTED = {"index.html", "files", "changelog"}


def listing(directory, path, parent=None):
    """Directory listing page: subdirectories first, then files with size and time."""
    entries = sorted((e for e in os.scandir(directory) if e.name not in UNLISTED), key=lambda e: e.name)
    rows = [f'<tr><td><a href="{parent}">../</a></td><td></td><td></td></tr>'] if parent else []
    for name in sorted({e.name for e in entries if e.is_dir()}):
        # absolute, as the root listing lives at /files/; a bare FreeBSD:14:amd64 would read as a URL scheme
        rows.append('<tr><td><a href="{}{}/">{}/</a></td><td>-</td><td>-</td></tr>'.format(
            quote(path, safe=":,+@/"), quote(name, safe=":,+@"), html.escape(name)))
    for e in entries:
        if not e.is_file():
            continue
        st = e.stat()
        when = datetime.datetime.fromtimestamp(st.st_mtime, datetime.timezone.utc)
        rows.append('<tr><td><a href="{}{}">{}</a></td><td>{}</td><td>{}</td></tr>'.format(
            quote(path, safe=":,+@/"), quote(e.name, safe=":,+@"), html.escape(e.name),
            when.strftime("%Y-%m-%d %H:%M"), f"{st.st_size:,}"))
    title = f"Index of {path}"
    body = (f'<h1>{html.escape(title)}</h1>\n<table class="listing">\n'
            '<thead><tr><th>Name</th><th>Modified (UTC)</th><th>Size</th></tr></thead>\n'
            '<tbody>\n%s\n</tbody>\n</table>' % "\n".join(rows))
    return page(body, title=title)


def index_tree(directory, path, parent):
    open(os.path.join(directory, "index.html"), "w").write(listing(directory, path, parent))
    for e in os.scandir(directory):
        if e.is_dir():
            index_tree(e.path, f"{path}{e.name}/", "../")


# the landing page owns the root's index.html; the dev channel is not listed
for e in os.scandir(REPO):
    if e.is_dir() and e.name not in UNLISTED:
        index_tree(e.path, f"/{e.name}/", "/files/")
os.makedirs(os.path.join(REPO, "files"), exist_ok=True)
open(os.path.join(REPO, "files", "index.html"), "w").write(listing(REPO, "/"))
