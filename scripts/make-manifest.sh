#!/usr/bin/env bash
# Regenerate MANIFEST.sha256 over every tracked file except the manifest itself.
set -euo pipefail
cd "$(dirname "$0")/.."
git ls-files | grep -v '^MANIFEST.sha256$' | sort | xargs sha256sum > MANIFEST.sha256
echo "MANIFEST.sha256: $(wc -l < MANIFEST.sha256) files"
