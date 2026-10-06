#!/usr/bin/env bash
# Watchtower installer. Pinned, checksummed, and confined to /workspace/watchtower.
# Usage: bash install.sh v0.1.0        install that tagged release
#        bash install.sh --scanners    add SkillSpector, husk and gitleaks (optional)
set -euo pipefail
WT_HOME="${WATCHTOWER_HOME:-/workspace/watchtower}"
REPO="https://github.com/ken-aisec/grokbot-watchtower"
GITLEAKS_VERSION="8.30.1"
TRUFFLEHOG_VERSION="3.97.9"
OSV_VERSION="2.6.0"

if [[ "${1:-}" == "--scanners" ]]; then
  python3 -m venv "$WT_HOME/scanners"
  "$WT_HOME/scanners/bin/pip" install --quiet --upgrade pip
  # Pinned: a security tool that installs unpinned scanners is its own supply-chain risk.
  "$WT_HOME/scanners/bin/pip" install --quiet \
    "skillspector @ git+https://github.com/NVIDIA/SkillSpector@a50b9c93835c94f7d36329f11c6599abbb9c74ee" \
    "husk-scanner==1.3.5" "pip-audit==2.10.1"
  mkdir -p "$WT_HOME/bin"
  arch="$(uname -m)"; case "$arch" in x86_64) ga=x64;; aarch64|arm64) ga=arm64;; *) echo "skip gitleaks: $arch"; ga="";; esac
  if [[ -n "$ga" ]]; then
    tgz="gitleaks_${GITLEAKS_VERSION}_linux_${ga}.tar.gz"
    base="https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}"
    curl -fsSL -o "/tmp/$tgz" "$base/$tgz"
    curl -fsSL -o /tmp/gitleaks_checksums.txt "$base/gitleaks_${GITLEAKS_VERSION}_checksums.txt"
    (cd /tmp && grep " $tgz\$" gitleaks_checksums.txt | sha256sum -c -)
    tar -xzf "/tmp/$tgz" -C "$WT_HOME/bin" gitleaks
    # TruffleHog: tells live keys from dead ones (asks each key's own provider)
    th="trufflehog_${TRUFFLEHOG_VERSION}_linux_$( [ "$ga" = x64 ] && echo amd64 || echo arm64 ).tar.gz"
    tb="https://github.com/trufflesecurity/trufflehog/releases/download/v${TRUFFLEHOG_VERSION}"
    curl -fsSL -o "/tmp/$th" "$tb/$th"
    curl -fsSL -o /tmp/trufflehog_checksums.txt "$tb/trufflehog_${TRUFFLEHOG_VERSION}_checksums.txt"
    (cd /tmp && grep " $th\$" trufflehog_checksums.txt | sha256sum -c -)
    tar -xzf "/tmp/$th" -C "$WT_HOME/bin" trufflehog
    # OSV-Scanner: known holes in Node, Go and other project dependencies
    ob="osv-scanner_linux_$( [ "$ga" = x64 ] && echo amd64 || echo arm64 )"
    curl -fsSL -o "$WT_HOME/bin/osv-scanner" "https://github.com/google/osv-scanner/releases/download/v${OSV_VERSION}/$ob"
    curl -fsSL -o /tmp/osv_sums.txt "https://github.com/google/osv-scanner/releases/download/v${OSV_VERSION}/osv-scanner_SHA256SUMS"
    (cd "$WT_HOME/bin" && grep " $ob\$" /tmp/osv_sums.txt | sed "s/$ob/osv-scanner/" | sha256sum -c -)
    chmod +x "$WT_HOME/bin/osv-scanner"
  fi
  "$WT_HOME/scanners/bin/skillspector" --version && "$WT_HOME/bin/gitleaks" version || true
  echo "Scanners installed in $WT_HOME (Watchtower finds them there automatically)."
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
