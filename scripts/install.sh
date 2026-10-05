#!/usr/bin/env bash
# Watchtower installer. Pinned, checksummed, and confined to /workspace/watchtower.
# Usage: bash install.sh v0.1.0        install that tagged release
#        bash install.sh --scanners    add SkillSpector, husk and gitleaks (optional)
set -euo pipefail
WT_HOME="${WATCHTOWER_HOME:-/workspace/watchtower}"
REPO="https://github.com/ken-aisec/grokbot-watchtower"
GITLEAKS_VERSION="8.21.2"

if [[ "${1:-}" == "--scanners" ]]; then
  python3 -m venv "$WT_HOME/.venv"
  "$WT_HOME/.venv/bin/pip" install --quiet --upgrade pip
  "$WT_HOME/.venv/bin/pip" install --quiet "git+https://github.com/NVIDIA/SkillSpector" husk-scanner pip-audit
  mkdir -p "$WT_HOME/bin"
  arch="$(uname -m)"; case "$arch" in x86_64) ga=x64;; aarch64|arm64) ga=arm64;; *) echo "skip gitleaks: $arch"; ga="";; esac
  if [[ -n "$ga" ]]; then
    tgz="gitleaks_${GITLEAKS_VERSION}_linux_${ga}.tar.gz"
    base="https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}"
    curl -fsSL -o "/tmp/$tgz" "$base/$tgz"
    curl -fsSL -o /tmp/gitleaks_checksums.txt "$base/gitleaks_${GITLEAKS_VERSION}_checksums.txt"
    (cd /tmp && grep " $tgz\$" gitleaks_checksums.txt | sha256sum -c -)
    tar -xzf "/tmp/$tgz" -C "$WT_HOME/bin" gitleaks
  fi
  echo "Scanners installed. Add to PATH in routines: export PATH=$WT_HOME/.venv/bin:$WT_HOME/bin:\$PATH"
  exit 0
fi

TAG="${1:?usage: install.sh <tag>  (for example v0.1.0)}"
mkdir -p "$WT_HOME"/{state,reports,exports,vet}
rm -rf "$WT_HOME/app.new"
git clone --quiet --depth 1 --branch "$TAG" "$REPO" "$WT_HOME/app.new"
(cd "$WT_HOME/app.new" && sha256sum --quiet -c MANIFEST.sha256) || { echo "MANIFEST CHECK FAILED - not installing"; rm -rf "$WT_HOME/app.new"; exit 1; }
rm -rf "$WT_HOME/app" && mv "$WT_HOME/app.new" "$WT_HOME/app"
python3 "$WT_HOME/app/watchtower/wt.py" --version >/dev/null
echo "Watchtower $TAG installed at $WT_HOME/app (manifest verified)."
