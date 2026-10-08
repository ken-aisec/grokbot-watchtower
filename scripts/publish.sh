#!/usr/bin/env bash
# Publish to GitHub. Works whether or not the repo already exists. Needs the GitHub CLI (`gh auth login`).
# Safe to rerun.
set -euo pipefail
cd "$(dirname "$0")/.."
OWNER="$(gh api user -q .login)"
REPO="$OWNER/grokbot-watchtower"
TAG="v0.6.5"
echo "Publishing $REPO ($TAG)"
if grep -rlq GITHUB_OWNER --exclude-dir=.git --exclude=publish.sh .; then
  grep -rl GITHUB_OWNER --exclude-dir=.git --exclude=publish.sh . | xargs perl -pi -e "s/GITHUB_OWNER/$OWNER/g"
  git add -A && git commit -qm "Set repository owner to $OWNER"
fi
python3 -W ignore::ResourceWarning -m unittest discover -s tests -q
git add -A   # new files must be tracked before the manifest lists them
bash scripts/make-manifest.sh
# Commit the whole release, not just the manifest, so the tag always points at the code that was tested.
git add -A && { git diff --cached --quiet || git commit -qm "Watchtower $TAG"; }
if gh repo view "$REPO" >/dev/null 2>&1; then
  echo "Repo exists; pushing to it."
  git remote get-url origin >/dev/null 2>&1 || git remote add origin "https://github.com/$REPO.git"
  if git fetch -q origin main 2>/dev/null && ! git merge-base --is-ancestor origin/main HEAD; then
    echo "GitHub has commits that aren't in this folder (for example a README). Overwrite them? Type yes:"
    read -r ok; [ "$ok" = "yes" ] || { echo "Stopped. Nothing pushed."; exit 1; }
    FORCE="--force"
  fi
  git push -u ${FORCE:-} origin main
else
  gh repo create "$REPO" --public --source . --push \
    --description "Read-only security watch for Grok Bot: vet templates before install, audit skills, routines and approvals, weekly report."
fi
if [ "$(gh repo view "$REPO" --json visibility -q .visibility)" != "PUBLIC" ]; then
  gh repo edit "$REPO" --visibility public --accept-visibility-change-consequences
  echo "Repo set to public so the Grok Bot installer can reach it."
fi
git tag -f -a "$TAG" -m "Watchtower $TAG" && git push -f origin "$TAG"
echo "Done: https://github.com/$REPO (tag $TAG)"
# The template's memories carry this release's tag and commit ID, so an installed copy can refuse anything else.
COMMIT="$(git rev-parse HEAD)"
python3 - "$TAG" "$COMMIT" <<'PYEOF' > template-memories.txt
import re, sys
tag, commit = sys.argv[1], sys.argv[2]
text = open("bot/memories.md").read().replace("{TAG}", tag).replace("{COMMIT}", commit)
for m in re.findall(r"(?m)^\d+\. (.+)$", text):
    print(m + "\n")
PYEOF
echo "Template memories for $TAG are in $(pwd)/template-memories.txt."
echo "Tell your Watchtower Bot: replace the template's memories with that text, then click Update template."
