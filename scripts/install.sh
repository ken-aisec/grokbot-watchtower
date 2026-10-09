#!/usr/bin/env bash
# Watchtower installer. Pinned, checksummed, and confined to /workspace/watchtower.
# Usage: bash install.sh v0.6.7 [commit]   install that tagged release; with a commit ID, refuse anything else
#        bash install.sh --scanners        add the optional scanners (second half of this file)
set -euo pipefail
WT_HOME="${WATCHTOWER_HOME:-/workspace/watchtower}"
REPO="https://github.com/ken-aisec/grokbot-watchtower"

if [[ "${1:-}" != "--scanners" ]]; then
  # ---- This is everything that runs for `bash install.sh <tag>`. It only writes inside $WT_HOME.
  TAG="${1:?usage: install.sh <tag> [commit]  (for example v0.6.7)}"; WANT="${2:-}"
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
# If the lock can't be used, the Python scanners are not installed without it (up to v0.6.6 this fell back to unchecked
# downloads). gitleaks, TruffleHog and OSV-Scanner don't come from the lock: they still install from their own checksums,
# and the script ends with CHECKSUM LOCK FAILED and a non-zero exit so the failure is never missed.
DL="${TMPDIR:-/tmp}"
LOCK_ERR="$DL/wt-lock.err"; LOCK_FAILED=""
if [[ -f "$LOCK" ]] && "$PIP" install --quiet --require-hashes -r "$LOCK" 2>"$LOCK_ERR" \
   && "$PIP" install --quiet --no-deps "$SS" 2>>"$LOCK_ERR"; then
  touch "$WT_HOME/scanners/LOCKED"; echo "Scanners installed from the checksum lock."
else
  LOCK_FAILED=1
  if [[ -f "$LOCK" ]]; then
    echo "CHECKSUM LOCK FAILED - not installing the Python scanners. pip refused the checksummed packages on this computer's Python ($(python3 --version 2>&1)):"
    tail -n 5 "$LOCK_ERR" 2>/dev/null | sed 's/^/  /' || true
  else
    echo "CHECKSUM LOCK FAILED - not installing the Python scanners: $LOCK is missing."
  fi
  echo "Nothing is installed without checksums. gitleaks, TruffleHog and OSV-Scanner still install from their own checksums."
  rm -rf "$WT_HOME/app.new"
fi
mkdir -p "$WT_HOME/bin"
arch="$(uname -m)"; case "$arch" in x86_64) ga=x64;; aarch64|arm64) ga=arm64;; *) echo "skip gitleaks: $arch"; ga="";; esac
if [[ -n "$ga" ]]; then
  # Each tool installs on its own: if one download or checksum fails, that tool is not installed, the others still are,
  # and the audit says which is missing. (&& chains on purpose: nothing is unpacked unless its checksum passed.)
  tgz="gitleaks_${GITLEAKS_VERSION}_linux_${ga}.tar.gz"
  base="https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}"
  curl -fsSL -o "$DL/$tgz" "$base/$tgz" \
    && curl -fsSL -o "$DL/gitleaks_checksums.txt" "$base/gitleaks_${GITLEAKS_VERSION}_checksums.txt" \
    && (cd "$DL" && grep " $tgz\$" gitleaks_checksums.txt | sha256sum -c -) \
    && tar -xzf "$DL/$tgz" -C "$WT_HOME/bin" gitleaks \
    || echo "gitleaks did not install; Watchtower works without it."
  # TruffleHog: tells live keys from dead ones (asks each key's own provider)
  th="trufflehog_${TRUFFLEHOG_VERSION}_linux_$( [ "$ga" = x64 ] && echo amd64 || echo arm64 ).tar.gz"
  tb="https://github.com/trufflesecurity/trufflehog/releases/download/v${TRUFFLEHOG_VERSION}"
  curl -fsSL -o "$DL/$th" "$tb/$th" \
    && curl -fsSL -o "$DL/trufflehog_checksums.txt" "$tb/trufflehog_${TRUFFLEHOG_VERSION}_checksums.txt" \
    && (cd "$DL" && grep " $th\$" trufflehog_checksums.txt | sha256sum -c -) \
    && tar -xzf "$DL/$th" -C "$WT_HOME/bin" trufflehog \
    || echo "TruffleHog did not install; Watchtower works without it."
  # OSV-Scanner: known holes in Node, Go and other project dependencies
  ob="osv-scanner_linux_$( [ "$ga" = x64 ] && echo amd64 || echo arm64 )"
  curl -fsSL -o "$WT_HOME/bin/osv-scanner.new" "https://github.com/google/osv-scanner/releases/download/v${OSV_VERSION}/$ob" \
    && curl -fsSL -o "$DL/osv_sums.txt" "https://github.com/google/osv-scanner/releases/download/v${OSV_VERSION}/osv-scanner_SHA256SUMS" \
    && (cd "$WT_HOME/bin" && grep " $ob\$" "$DL/osv_sums.txt" | sed "s/$ob/osv-scanner.new/" | sha256sum -c -) \
    && chmod +x "$WT_HOME/bin/osv-scanner.new" && mv "$WT_HOME/bin/osv-scanner.new" "$WT_HOME/bin/osv-scanner" \
    || { rm -f "$WT_HOME/bin/osv-scanner.new"; echo "OSV-Scanner did not install; Watchtower works without it."; }
fi
[[ -z "$LOCK_FAILED" ]] && { "$WT_HOME/scanners/bin/skillspector" --version || echo "SkillSpector did not install; Watchtower works without it and says so in the audit."; }
[[ -x "$WT_HOME/bin/gitleaks" ]] && "$WT_HOME/bin/gitleaks" version || true
rm -f "$DL"/gitleaks_*_linux_*.tar.gz "$DL/gitleaks_checksums.txt" "$DL"/trufflehog_*_linux_*.tar.gz "$DL/trufflehog_checksums.txt" "$DL/osv_sums.txt" "$LOCK_ERR"
if [[ -n "$LOCK_FAILED" ]]; then
  echo "CHECKSUM LOCK FAILED - the Python scanners (SkillSpector, husk) were not installed. Watchtower works without them and the audit says which are missing."
  exit 1
fi
echo "Scanners installed in $WT_HOME (Watchtower finds them there automatically)."
