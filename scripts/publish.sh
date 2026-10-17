#!/usr/bin/env bash
# Publish one reviewed release to GitHub. Needs the GitHub CLI (`gh auth login`).
# Usage: bash scripts/publish.sh <reviewed commit ID>
# It publishes exactly that commit: clean checkout of main, nothing untracked, manifest already committed. It never
# commits, never moves a tag, and stops on any check that fails. Safe to rerun.
set -euo pipefail
cd "$(dirname "$0")/.."
REVIEWED="${1:-}"
stop() { echo "STOPPED: $*. Nothing pushed."; exit 1; }
# The tag is wt.py's VERSION, which must be set exactly once: with two assignments Python reports the last one, and taking
# the first would tag the release with a number the installed copy doesn't report (Codex, batch 3 round 1). Round 2: counting
# matching lines missed valid Python such as `(VERSION) = "0.7.3"`, so the file is parsed: every binding of the name
# anywhere (assignment in any form, import, def, class, for, with, except, global, walrus, match, del) counts, and the one
# allowed is a top-level `VERSION = "x.y.z"`. Prints "<count> <version or nothing>".
VREAD="$(python3 -I - watchtower/wt.py <<'PYEOF' 2>/dev/null || true
import ast, re, sys
try:
    tree = ast.parse(open(sys.argv[1], encoding="utf-8").read())
except (OSError, SyntaxError, ValueError):
    print("0 "); sys.exit()
binds = []
for n in ast.walk(tree):
    names = []
    if isinstance(n, ast.Name) and not isinstance(n.ctx, ast.Load):
        names = [n.id]
    elif isinstance(n, ast.alias):
        names = [n.asname or n.name.split(".")[0]]
    elif isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        names = [n.name]
    elif isinstance(n, ast.ExceptHandler):
        names = [n.name or ""]
    elif isinstance(n, (ast.Global, ast.Nonlocal)):
        names = list(n.names)
    elif type(n).__name__ in ("MatchAs", "MatchStar"):
        names = [getattr(n, "name", None) or ""]
    elif type(n).__name__ == "MatchMapping":
        names = [getattr(n, "rest", None) or ""]
    binds += [n for x in names if x == "VERSION"]
one = [s for s in tree.body if isinstance(s, ast.Assign) and len(s.targets) == 1 and isinstance(s.targets[0], ast.Name)
       and s.targets[0].id == "VERSION" and isinstance(s.value, ast.Constant) and isinstance(s.value.value, str)
       and re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", s.value.value)]
print(len(binds), one[0].value.value if len(binds) == 1 and one else "")
PYEOF
)"
VCOUNT="${VREAD%% *}"
[[ "$VCOUNT" =~ ^[0-9]+$ ]] || VCOUNT=0
[[ "$VCOUNT" -le 1 ]] || stop "can't read VERSION from watchtower/wt.py: it is set $VCOUNT times. Set it once"
TAG="v${VREAD#* }"
[[ "$TAG" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || stop "can't read VERSION from watchtower/wt.py"
# Claude review 1 (3): the setup skill, the README and install.sh name the release to install and the version a good install
# prints. Nothing checked them, so after a version bump setup would reinstall the old release (or fail COMMIT CHECK) on every
# computer. Every version they name (in install.sh, on its lines naming install.sh) must be VERSION, and each must name it.
DOCS_PROBLEM="$(python3 -I - "${TAG#v}" <<'PYEOF' 2>&1 || true
import re, sys
want, bad = sys.argv[1], []
for rel, only in (("skills/watchtower-setup/SKILL.md", ""), ("README.md", ""), ("scripts/install.sh", "install.sh")):
    try:
        lines = open(rel, encoding="utf-8").read().splitlines()
    except (OSError, ValueError):
        bad.append(f"{rel} cannot be read"); continue
    seen = 0
    for n, line in enumerate(lines, 1):
        for v in re.findall(r"(?<![\w.])v?([0-9]+\.[0-9]+\.[0-9]+)(?![\w]|\.[0-9])", line) if only in line else []:
            seen += 1
            if v != want:
                bad.append(f"{rel} line {n} says {v}")
    if not seen:
        bad.append(f"{rel} names no version")
print(bad[0] + (f" (and {len(bad) - 1} more)" if len(bad) > 1 else "") if bad else "OK")
PYEOF
)"
[[ "$DOCS_PROBLEM" == "OK" ]] || stop "${DOCS_PROBLEM:-the versions in the release files could not be checked}: the setup skill, README and install.sh must name VERSION ${TAG#v}; update them, commit, and get that commit reviewed"
# Watchtower runs a scanner only when its program matches this lock, so a release without every checksum would leave that
# scanner unrun on every computer. scripts/scanner_lock.py is the same reader wt.py uses, so a line Watchtower would skip
# stops the release too. Fill the lock from `wt.py doctor` (scanner_check) after a fresh `install.sh --scanners`.
LOCK_PROBLEM="$(python3 -I scripts/scanner_lock.py scripts/scanner-bins.lock 2>&1)" \
  || stop "${LOCK_PROBLEM:-scripts/scanner-bins.lock could not be checked}. Run a fresh install.sh --scanners, then wt.py doctor, and copy each scanner_check sha256 into the lock"
[[ "$REVIEWED" =~ ^[0-9a-f]{40}$ ]] || stop "give the full 40-character commit ID that was reviewed (bash scripts/publish.sh <commit>)"
[[ "$(git rev-parse --abbrev-ref HEAD)" == "main" ]] || stop "publish from main (this checkout is on $(git rev-parse --abbrev-ref HEAD))"
[[ "$(git rev-parse HEAD)" == "$REVIEWED" ]] || stop "HEAD is $(git rev-parse HEAD), not the reviewed commit $REVIEWED"
[[ -z "$(git status --porcelain --untracked-files=all)" ]] || stop "the checkout has changed or untracked files; publish only the reviewed commit, as committed"
if grep -rlq GITHUB_OWNER --exclude-dir=.git --exclude=publish.sh .; then stop "GITHUB_OWNER placeholders are still in the release; set them, commit, and get that commit reviewed"; fi
OWNER="$(gh api user -q .login)" || stop "the GitHub CLI isn't signed in"
REPO="$OWNER/grokbot-watchtower"
echo "Publishing $REPO $TAG at $REVIEWED"
# A published tag is never moved: installed copies and template memories pin its commit.
if git rev-parse -q --verify "refs/tags/$TAG" >/dev/null || \
   { git remote get-url origin >/dev/null 2>&1 && git ls-remote --exit-code --tags origin "refs/tags/$TAG" >/dev/null 2>&1; }; then
  stop "tag $TAG already exists. Choose a new version number and set it as VERSION in watchtower/wt.py and in the release files"
fi
PYTHONDONTWRITEBYTECODE=1 python3 -W ignore::ResourceWarning -m unittest discover -s tests -q || stop "the tests failed"
bash scripts/make-manifest.sh
[[ -z "$(git status --porcelain --untracked-files=all)" ]] || { git checkout -q -- MANIFEST.sha256 2>/dev/null || true; stop "MANIFEST.sha256 in the reviewed commit is out of date; regenerate it, commit, and get that commit reviewed"; }
gh repo view "$REPO" >/dev/null 2>&1 || stop "$REPO doesn't exist on GitHub; create it first (this script no longer creates repos)"
git remote get-url origin >/dev/null 2>&1 || git remote add origin "https://github.com/$REPO.git"
git fetch -q origin main || stop "couldn't read main on GitHub"
git merge-base --is-ancestor origin/main "$REVIEWED" || stop "GitHub has commits on main that aren't in the reviewed commit; main is never overwritten"
[[ "$(gh repo view "$REPO" --json visibility -q .visibility)" == "PUBLIC" ]] || stop "$REPO is not public, so the installer can't reach it. Visibility is the owner's decision"
git push origin "$REVIEWED:refs/heads/main" || stop "the push to main failed"
[[ "$(git ls-remote origin refs/heads/main | cut -f1)" == "$REVIEWED" ]] || stop "main on GitHub isn't the reviewed commit after the push"
git tag -a "$TAG" "$REVIEWED" -m "Watchtower $TAG"
git push origin "refs/tags/$TAG" || stop "the tag push failed (the local tag $TAG is left for you to inspect)"
[[ "$(git ls-remote origin "refs/tags/$TAG^{}" | cut -f1)" == "$REVIEWED" ]] || stop "tag $TAG on GitHub doesn't point at the reviewed commit"
echo "Done: https://github.com/$REPO (tag $TAG = $REVIEWED; main = $REVIEWED)"
# The template's memories carry this release's tag and commit ID, so an installed copy can refuse anything else.
python3 - "$TAG" "$REVIEWED" <<'PYEOF' > "${TMPDIR:-/tmp}/template-memories-$TAG.txt"
import re, sys
tag, commit = sys.argv[1], sys.argv[2]
text = open("bot/memories.md").read().replace("{TAG}", tag).replace("{COMMIT}", commit)
for m in re.findall(r"(?m)^\d+\. (.+)$", text):
    print(m + "\n")
PYEOF
echo "Template memories for $TAG are in ${TMPDIR:-/tmp}/template-memories-$TAG.txt (outside the repo, so the checkout stays clean)."
echo "Tell your Watchtower Bot: replace the template's memories with that text, then click Update template."
