#!/usr/bin/env bash
# Watchtower installer. Pinned, checksummed, and confined to /workspace/watchtower.
# Usage: bash install.sh v0.6.6 [commit]   install that tagged release; with a commit ID, refuse anything else
#        bash install.sh --scanners        add the optional scanners (second half of this file)
set -euo pipefail
WT_HOME="${WATCHTOWER_HOME:-/workspace/watchtower}"
REPO="https://github.com/ken-aisec/grokbot-watchtower"

if [[ "${1:-}" != "--scanners" ]]; then
  # ---- This is everything that runs for `bash install.sh <tag>`. It only writes inside $WT_HOME.
  TAG="${1:?usage: install.sh <tag> [commit]  (for example v0.6.6)}"; WANT="${2:-}"
  mkdir -p "$WT_HOME"/{state,reports,exports,vet}
  rm -rf "$WT_HOME/app.new"
  git -c advice.detachedHead=false clone --quiet --depth 1 --branch "$TAG" "$REPO" "$WT_HOME/app.new"
  GOT="$(git -C "$WT_HOME/app.new" rev-parse HEAD)"
  # The commit ID is a checksum of every file. When the template gives one, a changed tag or repo can't slip through.
  if [[ -n "$WANT" && "$GOT" != "$WANT" ]]; then
    echo "COMMIT CHECK FAILED - not installing (wanted $WANT, the tag points at $GOT)"; rm -rf "$WT_HOME/app.new"; exit 1
  fi
  (cd "$WT_HOME/app.new" && sha256sum --quiet -c MANIFEST.sha256) || { echo "MANIFEST CHECK FAILED - not installing"; rm -rf "$WT_HOME/app.new"; exit 1; }
  rm -rf "$WT_HOME/app" && mv "$WT_HOME/app.new" "$WT_HOME/app"
  python3 "$WT_HOME/app/watchtower/wt.py" --version >/dev/null
  echo "Watchtower $TAG installed at $WT_HOME/app (commit $GOT, manifest verified$([[ -n "$WANT" ]] && echo ", commit matches the template"))."
  echo "NEXT: read $WT_HOME/app/skills/watchtower-setup/SKILL.md and follow it from section 2."
  echo "Your skills are the SKILL.md files under $WT_HOME/app/skills/<name>/. Read the one you need when asked; never edit them."
  exit 0
fi

# ---- Optional scanners: bash install.sh --scanners
GITLEAKS_VERSION="8.30.1"
TRUFFLEHOG_VERSION="3.97.9"
OSV_VERSION="2.6.0"
python3 -m venv "$WT_HOME/scanners" || { echo "This computer can't create a Python environment, so the Python scanners are skipped."; }
PIP="$WT_HOME/scanners/bin/pip"; LOCK="$WT_HOME/app/scripts/scanners.lock"; rm -f "$WT_HOME/scanners/LOCKED"
SS="skillspector @ git+https://github.com/NVIDIA/SkillSpector@a50b9c93835c94f7d36329f11c6599abbb9c74ee"
# Pinned and checksummed: a security tool that installs unpinned scanners is its own supply-chain risk.
# The lock lists every package the scanners need with its checksum; pip refuses anything that doesn't match.
if [[ -f "$LOCK" ]] && "$PIP" install --quiet --require-hashes -r "$LOCK" 2>/tmp/wt-lock.err \
   && "$PIP" install --quiet --no-deps "$SS"; then
  touch "$WT_HOME/scanners/LOCKED"; echo "Scanners installed from the checksum lock."
else
  echo "The checksum lock doesn't fit this computer's Python ($(python3 --version 2>&1)); installing the pinned versions without it."
  "$PIP" install --quiet "$SS" "husk-scanner==1.3.5" "pip-audit==2.10.1" || echo "The Python scanners did not install; Watchtower works without them."
fi
mkdir -p "$WT_HOME/bin"
arch="$(uname -m)"; case "$arch" in x86_64) ga=x64;; aarch64|arm64) ga=arm64;; *) echo "skip gitleaks: $arch"; ga="";; esac
if [[ -n "$ga" ]]; then
  # Each tool installs on its own: if one download or checksum fails, that tool is not installed, the others still are,
  # and the audit says which is missing. (&& chains on purpose: nothing is unpacked unless its checksum passed.)
  tgz="gitleaks_${GITLEAKS_VERSION}_linux_${ga}.tar.gz"
  base="https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}"
  curl -fsSL -o "/tmp/$tgz" "$base/$tgz" \
    && curl -fsSL -o /tmp/gitleaks_checksums.txt "$base/gitleaks_${GITLEAKS_VERSION}_checksums.txt" \
    && (cd /tmp && grep " $tgz\$" gitleaks_checksums.txt | sha256sum -c -) \
    && tar -xzf "/tmp/$tgz" -C "$WT_HOME/bin" gitleaks \
    || echo "gitleaks did not install; Watchtower works without it."
  # TruffleHog: tells live keys from dead ones (asks each key's own provider)
  th="trufflehog_${TRUFFLEHOG_VERSION}_linux_$( [ "$ga" = x64 ] && echo amd64 || echo arm64 ).tar.gz"
  tb="https://github.com/trufflesecurity/trufflehog/releases/download/v${TRUFFLEHOG_VERSION}"
  curl -fsSL -o "/tmp/$th" "$tb/$th" \
    && curl -fsSL -o /tmp/trufflehog_checksums.txt "$tb/trufflehog_${TRUFFLEHOG_VERSION}_checksums.txt" \
    && (cd /tmp && grep " $th\$" trufflehog_checksums.txt | sha256sum -c -) \
    && tar -xzf "/tmp/$th" -C "$WT_HOME/bin" trufflehog \
    || echo "TruffleHog did not install; Watchtower works without it."
  # OSV-Scanner: known holes in Node, Go and other project dependencies
  ob="osv-scanner_linux_$( [ "$ga" = x64 ] && echo amd64 || echo arm64 )"
  curl -fsSL -o "$WT_HOME/bin/osv-scanner.new" "https://github.com/google/osv-scanner/releases/download/v${OSV_VERSION}/$ob" \
    && curl -fsSL -o /tmp/osv_sums.txt "https://github.com/google/osv-scanner/releases/download/v${OSV_VERSION}/osv-scanner_SHA256SUMS" \
    && (cd "$WT_HOME/bin" && grep " $ob\$" /tmp/osv_sums.txt | sed "s/$ob/osv-scanner.new/" | sha256sum -c -) \
    && chmod +x "$WT_HOME/bin/osv-scanner.new" && mv "$WT_HOME/bin/osv-scanner.new" "$WT_HOME/bin/osv-scanner" \
    || { rm -f "$WT_HOME/bin/osv-scanner.new"; echo "OSV-Scanner did not install; Watchtower works without it."; }
fi
"$WT_HOME/scanners/bin/skillspector" --version || echo "SkillSpector did not install; Watchtower works without it and says so in the audit."
[[ -x "$WT_HOME/bin/gitleaks" ]] && "$WT_HOME/bin/gitleaks" version || true
rm -f /tmp/gitleaks_*_linux_*.tar.gz /tmp/gitleaks_checksums.txt /tmp/trufflehog_*_linux_*.tar.gz /tmp/trufflehog_checksums.txt /tmp/osv_sums.txt /tmp/wt-lock.err
echo "Scanners installed in $WT_HOME (Watchtower finds them there automatically)."
