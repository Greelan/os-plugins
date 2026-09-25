#!/usr/bin/env python3
# Fetch the pure-Python libraries plugins vendor under scripts/*/*/lib/ from PyPI. Only the
# lib/VENDOR pins are committed; the build fetches the libraries before packaging.
# Each lib/VENDOR lists "<PyPI name> <version> <package dir in sdist> <license file in sdist>".
#
#   vendor.py check                 list vendored libraries with a newer PyPI release
#   vendor.py update [--latest]     fetch the pinned (or latest, updating the pins) versions,
#                                   verifying hashes
#
# After raising a pin, bump PLUGIN_REVISION and the changelog of each plugin that changed.
import glob
import hashlib
import io
import json
import os
import shutil
import sys
import tarfile
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# oldest Python an OPNsense series still in use ships (25.7)
MIN_PYTHON = (3, 11)


def manifests():
    return sorted(glob.glob(os.path.join(ROOT, "*", "*", "src", "opnsense", "scripts", "*", "*", "lib", "VENDOR")))


def read_manifest(path):
    header, entries = [], []
    for line in open(path):
        if line.startswith("#") or not line.strip():
            header.append(line)
        else:
            entries.append(line.split())
    return header, entries


def pypi(name, version=None):
    url = f"https://pypi.org/pypi/{name}/{version}/json" if version else f"https://pypi.org/pypi/{name}/json"
    with urllib.request.urlopen(url, timeout=60) as response:
        return json.load(response)


def supports_min_python(requires):
    """True unless requires_python excludes MIN_PYTHON (only >= bounds are understood)."""
    for spec in (requires or "").split(","):
        spec = spec.strip()
        if spec.startswith(">="):
            bound = tuple(int(p) for p in spec[2:].split(".")[:2] if p.isdigit())
            if bound > MIN_PYTHON:
                return False
    return True


def check():
    outdated = []
    for path in manifests():
        for name, version, _, _ in read_manifest(path)[1]:
            latest = pypi(name)["info"]["version"]
            if latest != version:
                outdated.append(f"{name} {version} -> {latest} ({os.path.relpath(path, ROOT)})")
    print("\n".join(outdated))


def vendor(libdir, name, version, package_dir, license_file):
    release = pypi(name, version)
    if not supports_min_python(release["info"].get("requires_python")):
        sys.exit(f"{name} {version} requires Python {release['info']['requires_python']}, "
                 f"OPNsense still ships {'.'.join(map(str, MIN_PYTHON))}")
    sdist = next((u for u in release["urls"] if u["packagetype"] == "sdist"), None)
    if sdist is None:
        sys.exit(f"{name} {version} has no source distribution on PyPI")
    with urllib.request.urlopen(sdist["url"], timeout=120) as response:
        data = response.read()
    if hashlib.sha256(data).hexdigest() != sdist["digests"]["sha256"]:
        sys.exit(f"{sdist['filename']} does not match the SHA-256 PyPI publishes")

    with tarfile.open(fileobj=io.BytesIO(data)) as archive:
        top = archive.getnames()[0].split("/")[0]
        prefix = f"{top}/{package_dir}/"
        target = os.path.join(libdir, os.path.basename(package_dir))
        shutil.rmtree(target, ignore_errors=True)
        for member in archive.getmembers():
            if not member.isfile() or not member.name.startswith(prefix) or "__pycache__" in member.name:
                continue
            dest = os.path.realpath(os.path.join(target, member.name[len(prefix):]))
            if not dest.startswith(os.path.realpath(target) + os.sep):
                sys.exit(f"{sdist['filename']} has a member outside {package_dir}: {member.name}")
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            with open(dest, "wb") as handle:
                handle.write(archive.extractfile(member).read())
        license_data = archive.extractfile(f"{top}/{license_file}").read()
        with open(os.path.join(target, os.path.basename(license_file)), "wb") as handle:
            handle.write(license_data)
    print(f"vendored {name} {version} into {os.path.relpath(target, ROOT)}")


def update(latest):
    for path in manifests():
        header, entries = read_manifest(path)
        for entry in entries:
            if latest:
                entry[1] = pypi(entry[0])["info"]["version"]
            vendor(os.path.dirname(path), *entry)
        with open(path, "w") as handle:
            handle.writelines(header + [" ".join(entry) + "\n" for entry in entries])


if __name__ == "__main__":
    if sys.argv[1:] == ["check"]:
        check()
    elif sys.argv[1:2] == ["update"] and sys.argv[2:] in ([], ["--latest"]):
        update(sys.argv[2:] == ["--latest"])
    else:
        sys.exit(f"usage: {sys.argv[0]} check | update [--latest]")
