#!/usr/bin/env bash
# One-time publish: needs the GitHub CLI (`gh auth login` first).
set -euo pipefail
cd "$(dirname "$0")/.."
OWNER="$(gh api user -q .login)"
echo "Publishing as $OWNER/grokbot-watchtower"
grep -rl GITHUB_OWNER --exclude-dir=.git . | xargs perl -pi -e "s/GITHUB_OWNER/$OWNER/g"
python3 -m unittest discover -s tests -q
git add -A && git commit -qm "Set repository owner to $OWNER"
bash scripts/make-manifest.sh && git add MANIFEST.sha256 && git commit -qm "Manifest for v0.1.1"
gh repo create "$OWNER/grokbot-watchtower" --public --source . --push \
  --description "Read-only security watch for Grok Bot: vet templates before install, audit skills, routines and approvals, weekly report."
git tag -a v0.1.1 -m "Watchtower v0.1.1" && git push -q origin v0.1.1
echo "Done: https://github.com/$OWNER/grokbot-watchtower (tag v0.1.1)"
