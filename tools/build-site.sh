#!/bin/sh
# Render the site into repo/ (needs python3 + markdown); runs on the deploy runner.
set -e
exec python3 "$(cd "$(dirname "$0")" && pwd)/build-site.py"
