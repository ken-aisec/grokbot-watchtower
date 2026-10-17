"""install.sh and publish.sh, run for real with stand-ins for pip, curl and gh. Nothing here reaches the network or GitHub."""
import hashlib, io, os, platform, shutil, subprocess, sys, tarfile, tempfile, unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
REAL_PY = shutil.which("python3") or sys.executable
GIT_ENV = {"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid", "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid",
           "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1", "GIT_TERMINAL_PROMPT": "0"}


SCANNER_NAMES = ("skillspector", "husk", "gitleaks", "trufflehog", "osv-scanner", "pip-audit")
VERSIONED_DOCS = ("skills/watchtower-setup/SKILL.md", "README.md", "scripts/install.sh")


def real_version():
    return open(os.path.join(ROOT, "watchtower", "wt.py")).read().split('\nVERSION = "')[1].split('"')[0]


def stub(d, name, body):
    p = os.path.join(d, name)
    open(p, "w").write("#!/bin/bash\n" + body)
    os.chmod(p, 0o755)


class InstallScanners(unittest.TestCase):
    """Up to v0.6.6, when the checksum lock didn't fit, install.sh said so and installed the scanners without it."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.wt = os.path.join(self.tmp, "wt"); self.bin = os.path.join(self.tmp, "bin"); self.log = os.path.join(self.tmp, "calls.log")
        os.makedirs(os.path.join(self.wt, "app", "scripts")); os.makedirs(os.path.join(self.wt, "app.new")); os.makedirs(self.bin)
        os.makedirs(os.path.join(self.tmp, "t"))
        self.lock = os.path.join(self.wt, "app", "scripts", "scanners.lock")
        open(self.lock, "w").write("husk-scanner==1.3.5 --hash=sha256:00\n")
        pip = ('echo "pip $*" >> "$CALLS"\n'
               'if [[ "$*" == *--require-hashes* && -n "$PIP_FAILS" ]]; then\n'
               '  echo "ERROR: THESE PACKAGES DO NOT MATCH THE HASHES FROM THE REQUIREMENTS FILE. If you have updated the package versions, please update the hashes." >&2; exit 1\nfi\nexit 0\n')
        open(os.path.join(self.tmp, "pip.body"), "w").write(pip)
        stub(self.bin, "python3", f'if [[ "$1" == "-m" && "$2" == "venv" ]]; then mkdir -p "$3/bin"; cp "{self.tmp}/pip.body" "$3/bin/pip"; '
                                  f'sed -i "1i #!/bin/bash" "$3/bin/pip"; chmod +x "$3/bin/pip"; printf "#!/bin/bash\\necho SkillSpector v0\\n" > "$3/bin/skillspector"; '
                                  f'chmod +x "$3/bin/skillspector"; exit 0; fi\nexec {REAL_PY} "$@"\n')
        self.serve = os.path.join(self.tmp, "releases"); os.makedirs(self.serve)
        self.release_files()
        stub(self.bin, "curl", 'echo "curl $*" >> "$CALLS"\nout=""; url=""\nwhile [[ $# -gt 0 ]]; do case "$1" in -o) out="$2"; shift 2;; -*) shift;; *) url="$1"; shift;; esac; done\n'
                               'f="$SERVE/${url##*/}"; [[ -f "$f" ]] || exit 22; cp "$f" "$out"\n')

    def release_files(self):
        """Stand-ins for the gitleaks, TruffleHog and OSV-Scanner release downloads, each with its published checksum file."""
        a = {"x86_64": ("x64", "amd64"), "aarch64": ("arm64", "arm64"), "arm64": ("arm64", "arm64")}.get(platform.machine())
        if not a:
            self.skipTest("install.sh skips the binary scanners on " + platform.machine())
        def tgz(name, tool):
            buf = io.BytesIO()
            with tarfile.open(fileobj=buf, mode="w:gz") as t:
                body = f"#!/bin/bash\necho {tool} test build\n".encode()
                info = tarfile.TarInfo(tool); info.size = len(body); info.mode = 0o755
                t.addfile(info, io.BytesIO(body))
            open(os.path.join(self.serve, name), "wb").write(buf.getvalue())
            return hashlib.sha256(buf.getvalue()).hexdigest()
        g = f"gitleaks_8.30.1_linux_{a[0]}.tar.gz"; th = f"trufflehog_3.97.9_linux_{a[1]}.tar.gz"; ob = f"osv-scanner_linux_{a[1]}"
        open(os.path.join(self.serve, "gitleaks_8.30.1_checksums.txt"), "w").write(f"{tgz(g, 'gitleaks')}  {g}\n")
        open(os.path.join(self.serve, "trufflehog_3.97.9_checksums.txt"), "w").write(f"{tgz(th, 'trufflehog')}  {th}\n")
        body = b"#!/bin/bash\necho osv-scanner test build\n"
        open(os.path.join(self.serve, ob), "wb").write(body)
        open(os.path.join(self.serve, "osv-scanner_SHA256SUMS"), "w").write(f"{hashlib.sha256(body).hexdigest()}  {ob}\n")

    def binaries(self):
        return sorted(f for f in ("gitleaks", "trufflehog", "osv-scanner") if os.access(os.path.join(self.wt, "scanners", "bin", f), os.X_OK))

    def run_install(self, **env):
        e = dict(os.environ, PATH=self.bin + ":" + os.environ["PATH"], WATCHTOWER_HOME=self.wt, CALLS=self.log, SERVE=self.serve, TMPDIR=os.path.join(self.tmp, "t"), **env)
        r = subprocess.run(["bash", os.path.join(ROOT, "scripts", "install.sh"), "--scanners"], env=e, capture_output=True, text=True, timeout=60)
        calls = open(self.log).read().splitlines() if os.path.exists(self.log) else []
        return r, calls

    def test_a_lock_that_fails_stops_the_install(self):
        """Ken, Oct 9: a failed lock skips only the Python scanners. The binaries still install from their own checksums,
        and the script still ends with CHECKSUM LOCK FAILED and a non-zero exit."""
        r, calls = self.run_install(PIP_FAILS="1")
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("CHECKSUM LOCK FAILED", r.stdout)
        self.assertIn("DO NOT MATCH THE HASHES", r.stdout)                          # it says why
        self.assertEqual([c for c in calls if c.startswith("pip")], [f"pip install --quiet --require-hashes -r {self.lock}"])   # nothing without the lock
        self.assertEqual(self.binaries(), ["gitleaks", "osv-scanner", "trufflehog"], r.stdout)   # the others come from their own checksums
        self.assertTrue(r.stdout.rstrip().splitlines()[-1].startswith("CHECKSUM LOCK FAILED"), r.stdout)   # the last word, not lost above
        self.assertNotIn("Scanners installed in", r.stdout)
        self.assertFalse(os.path.exists(os.path.join(self.wt, "app.new")))
        self.assertFalse(os.path.exists(os.path.join(self.wt, "scanners", "LOCKED")))
        self.assertEqual(os.listdir(os.path.join(self.tmp, "t")), [])                # downloads and the pip log are cleaned up

    def test_a_missing_lock_stops_the_install(self):
        os.remove(self.lock)
        r, calls = self.run_install()
        self.assertEqual(r.returncode, 1)
        self.assertIn("is missing", r.stdout)
        self.assertIn("CHECKSUM LOCK FAILED", r.stdout)
        self.assertEqual([c for c in calls if c.startswith("pip")], [])
        self.assertEqual(self.binaries(), ["gitleaks", "osv-scanner", "trufflehog"], r.stdout)
        self.assertFalse(os.path.exists(os.path.join(self.wt, "scanners", "LOCKED")))

    def test_a_binary_with_a_wrong_checksum_is_not_installed(self):
        open(os.path.join(self.serve, "gitleaks_8.30.1_checksums.txt"), "w").write("0" * 64 + f"  gitleaks_8.30.1_linux_{'x64' if platform.machine() == 'x86_64' else 'arm64'}.tar.gz\n")
        r, calls = self.run_install(PIP_FAILS="1")
        self.assertEqual(r.returncode, 1)
        self.assertEqual(self.binaries(), ["osv-scanner", "trufflehog"], r.stdout)

    def test_a_lock_that_fits_still_installs(self):
        r, calls = self.run_install()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertTrue(os.path.exists(os.path.join(self.wt, "scanners", "LOCKED")))
        self.assertIn("Scanners installed from the checksum lock.", r.stdout)
        self.assertEqual(self.binaries(), ["gitleaks", "osv-scanner", "trufflehog"], r.stdout)

    def test_batch3_go_tools_move_to_the_checked_folder(self):
        """Batch 3 (R7): Watchtower runs scanners only from scanners/bin, so the Go tools install there and the old copies go."""
        old = os.path.join(self.wt, "bin"); os.makedirs(old)
        for f in ("gitleaks", "trufflehog", "osv-scanner"):
            stub(old, f, "echo old copy\n")
        r, _ = self.run_install()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(self.binaries(), ["gitleaks", "osv-scanner", "trufflehog"], r.stdout)
        self.assertEqual(os.listdir(old), [])                                      # the legacy copies are removed
        self.assertIn("only when each matches scripts/scanner-bins.lock", r.stdout)

    def test_claude1_a_repointed_scanner_python_is_replaced(self):
        """Claude review 1 (6): `python3 -m venv` leaves an existing scanners/bin/python* link alone, so the reinstall WT-X005
        asks for kept a re-pointed Python (and install's own pip ran through it)."""
        sb = os.path.join(self.wt, "scanners", "bin"); os.makedirs(sb)
        evil = os.path.join(self.tmp, "evil-python"); stub(self.tmp, "evil-python", "exit 0\n")
        for n in ("python", "python3", "python3.12"):
            os.symlink(evil, os.path.join(sb, n))
        r, _ = self.run_install()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        for n in ("python", "python3", "python3.12"):
            p = os.path.join(sb, n)
            self.assertFalse(os.path.lexists(p) and os.path.realpath(p) == evil, n)

    def test_claude2_a_swapped_entry_point_and_a_planted_pip_are_replaced(self):
        """Claude review 2 (4): `python3 -m venv` on an existing environment leaves bin/pip and the entry points alone (ensurepip
        and pip skip what is already installed), so the reinstall WT-X005 asks for kept a swapped skillspector, and a planted pip
        ran and could print the success line and touch LOCKED. The venv here is real; only pip's "already installed" is a stand-in."""
        stub(self.bin, "python3", f'if [[ "$1" == "-m" && "$2" == "venv" ]]; then {REAL_PY} -m venv --without-pip "$3" || exit 1; '
                                  f'[[ -e "$3/bin/pip" ]] || {{ cp "{self.tmp}/pip.body" "$3/bin/pip"; sed -i "1i #!/bin/bash" "$3/bin/pip"; chmod +x "$3/bin/pip"; }}; '
                                  f'[[ -e "$3/bin/skillspector" ]] || {{ printf "#!/bin/bash\\necho SkillSpector v0\\n" > "$3/bin/skillspector"; chmod +x "$3/bin/skillspector"; }}; '
                                  f'exit 0; fi\nexec {REAL_PY} "$@"\n')
        sb = os.path.join(self.wt, "scanners", "bin"); os.makedirs(sb)
        pwned = os.path.join(self.tmp, "planted-pip-ran")
        stub(sb, "pip", f'touch "{pwned}"; touch "$WATCHTOWER_HOME/scanners/LOCKED"; exit 0\n')
        stub(sb, "skillspector", "echo SWAPPED\n")
        r, _ = self.run_install()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertFalse(os.path.exists(pwned), r.stdout)
        self.assertNotIn("SWAPPED", open(os.path.join(sb, "skillspector")).read())

    def test_claude2_contrast_a_linked_scanners_folder_is_not_emptied(self):
        """Contrast: passes on 150144a too. The fresh environment removes a link named scanners, never what it points to."""
        target = os.path.join(self.tmp, "owner-files"); os.makedirs(target)
        open(os.path.join(target, "keep.txt"), "w").write("mine\n")
        os.symlink(target, os.path.join(self.wt, "scanners"))
        r, _ = self.run_install()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(open(os.path.join(target, "keep.txt")).read(), "mine\n")

    def test_batch3_a_failed_download_keeps_the_old_copy(self):
        """Contrast (Codex, batch 3 round 1): passes on 7cf8996 too, where the installer never removed the old copy at all."""
        os.makedirs(os.path.join(self.wt, "bin"))
        stub(os.path.join(self.wt, "bin"), "gitleaks", "echo old copy\n")
        os.remove(os.path.join(self.serve, "gitleaks_8.30.1_checksums.txt"))
        r, _ = self.run_install()
        self.assertNotIn("gitleaks", self.binaries())
        self.assertTrue(os.path.exists(os.path.join(self.wt, "bin", "gitleaks")))   # nothing new arrived, so nothing was taken away


class Publish(unittest.TestCase):
    """publish.sh offered to force-push over GitHub's main, moved tags with `tag -f` / `push -f`, and made a private repo public."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.repo = os.path.join(self.tmp, "repo"); self.remote = os.path.join(self.tmp, "remote.git"); self.bin = os.path.join(self.tmp, "bin")
        self.ghlog = os.path.join(self.tmp, "gh.log")
        for d in ("scripts", "tests", "bot", "watchtower"):
            os.makedirs(os.path.join(self.repo, d))
        os.makedirs(self.bin)
        shutil.copy(os.path.join(ROOT, "scripts", "publish.sh"), os.path.join(self.repo, "scripts"))
        shutil.copy(os.path.join(ROOT, "scripts", "scanner_lock.py"), os.path.join(self.repo, "scripts"))   # batch 3 round 1: the lock reader publish.sh runs
        # Batch 3: publish.sh reads the tag from wt.py's VERSION and needs a checksum for every scanner in the lock.
        open(os.path.join(self.repo, "watchtower", "wt.py"), "w").write(f'VERSION = "{real_version()}"\n')
        open(os.path.join(self.repo, "scripts", "scanner-bins.lock"), "w").write(
            "".join(f"{hashlib.sha256(n.encode()).hexdigest()}  {n}  x86_64  test\n" for n in SCANNER_NAMES))
        # Claude review 1 (3): publish.sh holds the setup skill, README and install.sh to VERSION. The real ones, as committed.
        for rel in VERSIONED_DOCS:
            os.makedirs(os.path.dirname(os.path.join(self.repo, rel)), exist_ok=True)
            shutil.copy(os.path.join(ROOT, rel), os.path.join(self.repo, rel))
        open(os.path.join(self.repo, "scripts", "make-manifest.sh"), "w").write("#!/bin/bash\necho manifest > MANIFEST.sha256\n")
        open(os.path.join(self.repo, "tests", "test_ok.py"), "w").write("import unittest\nclass T(unittest.TestCase):\n    def test_ok(self):\n        pass\n")
        open(os.path.join(self.repo, "bot", "memories.md"), "w").write("1. Install {TAG} at {COMMIT}.\n")
        open(os.path.join(self.repo, "MANIFEST.sha256"), "w").write("manifest\n")   # the reviewed commit carries its manifest
        stub(self.bin, "gh", 'echo "gh $*" >> "$GHLOG"\n'
                             'if [[ "$1 $2" == "api user" ]]; then echo ownerx; exit 0; fi\n'
                             'if [[ "$1 $2" == "repo view" && "$*" == *visibility* ]]; then echo "$FAKE_VIS"; exit 0; fi\n'
                             'if [[ "$1 $2" == "repo view" ]]; then exit 0; fi\nexit 0\n')
        self.git("init", "-q", "-b", "main"); self.git("add", "-A"); self.git("commit", "-qm", "first")
        subprocess.run(["git", "init", "-q", "--bare", "-b", "main", self.remote], check=True, env=dict(os.environ, **GIT_ENV))
        self.git("remote", "add", "origin", self.remote); self.git("push", "-q", "origin", "main")

    def git(self, *a, cwd=None):
        return subprocess.run(["git", *a], cwd=cwd or self.repo, check=True, capture_output=True, text=True, env=dict(os.environ, **GIT_ENV)).stdout.strip()

    def remote_ref(self, ref):
        r = subprocess.run(["git", "--git-dir", self.remote, "rev-parse", "-q", "--verify", ref], capture_output=True, text=True)
        return r.stdout.strip() or None

    def publish(self, vis="PUBLIC", reviewed=None):
        """R14: publish.sh takes the reviewed commit ID; by default the checkout's HEAD is the reviewed candidate."""
        e = dict(os.environ, PATH=self.bin + ":" + os.environ["PATH"], GHLOG=self.ghlog, FAKE_VIS=vis, **GIT_ENV)
        reviewed = reviewed or self.git("rev-parse", "HEAD")
        r = subprocess.run(["bash", "scripts/publish.sh", reviewed], cwd=self.repo, env=e, input="yes\n", capture_output=True, text=True, timeout=120)
        return r, (open(self.ghlog).read() if os.path.exists(self.ghlog) else "")

    def tag(self):
        return "v" + open(os.path.join(self.repo, "watchtower", "wt.py")).read().split('VERSION = "')[1].split('"')[0]

    def test_an_existing_tag_is_never_moved(self):
        self.git("tag", "-a", self.tag(), "-m", "old"); self.git("push", "-q", "origin", self.tag()); self.git("tag", "-d", self.tag())
        old = self.remote_ref(f"refs/tags/{self.tag()}")
        open(os.path.join(self.repo, "new.txt"), "w").write("x"); self.git("add", "-A"); self.git("commit", "-qm", "new")
        r, _ = self.publish()
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("already exists", r.stdout)
        self.assertEqual(self.remote_ref(f"refs/tags/{self.tag()}"), old)

    def test_githubs_main_is_never_overwritten(self):
        other = os.path.join(self.tmp, "other")
        subprocess.run(["git", "clone", "-q", self.remote, other], check=True, env=dict(os.environ, **GIT_ENV))
        open(os.path.join(other, "README.md"), "w").write("added on GitHub"); self.git("add", "-A", cwd=other); self.git("commit", "-qm", "readme", cwd=other)
        self.git("push", "-q", "origin", "main", cwd=other)
        theirs = self.remote_ref("refs/heads/main")
        r, _ = self.publish()                                                         # the old script asked "Overwrite them? Type yes" and force-pushed on yes
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertNotIn("Type yes", r.stdout)
        self.assertEqual(self.remote_ref("refs/heads/main"), theirs)
        self.assertIsNone(self.remote_ref(f"refs/tags/{self.tag()}"))

    def test_a_private_repo_is_never_made_public(self):
        r, gh = self.publish(vis="PRIVATE")
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("is not public", r.stdout)
        self.assertNotIn("repo edit", gh)
        self.assertIsNone(self.remote_ref(f"refs/tags/{self.tag()}"))

    def test_a_new_version_on_a_public_repo_still_publishes(self):
        r, gh = self.publish()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(self.remote_ref(f"refs/tags/{self.tag()}^{{commit}}"), self.git("rev-parse", "HEAD"))
        self.assertNotIn("repo edit", gh)

    def test_r14_untracked_files_are_never_committed_or_tagged(self):
        """Adversarial review R14: `git add -A` committed whatever was lying in the folder, then tagged that HEAD."""
        reviewed = self.git("rev-parse", "HEAD")
        open(os.path.join(self.repo, "notes-private.txt"), "w").write("not for release")
        r, _ = self.publish(reviewed=reviewed)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("untracked", r.stdout)
        self.assertEqual(self.git("rev-parse", "HEAD"), reviewed)                       # nothing was committed
        self.assertIsNone(self.remote_ref(f"refs/tags/{self.tag()}"))

    def test_r14_only_the_reviewed_commit_is_published(self):
        reviewed = self.git("rev-parse", "HEAD")
        open(os.path.join(self.repo, "later.txt"), "w").write("x"); self.git("add", "-A"); self.git("commit", "-qm", "after review")
        r, _ = self.publish(reviewed=reviewed)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("not the reviewed commit", r.stdout)
        self.assertIsNone(self.remote_ref(f"refs/tags/{self.tag()}"))
        self.assertNotEqual(self.remote_ref("refs/heads/main"), self.git("rev-parse", "HEAD"))

    def test_r14_wrong_branch_or_missing_id_stops(self):
        r, _ = self.publish(reviewed="main")
        self.assertEqual(r.returncode, 1); self.assertIn("40-character", r.stdout)
        self.git("checkout", "-qb", "dev")
        r, _ = self.publish()
        self.assertEqual(r.returncode, 1); self.assertIn("publish from main", r.stdout)

    def test_r14_main_tag_and_reviewed_commit_agree(self):
        reviewed = self.git("rev-parse", "HEAD")
        r, _ = self.publish(reviewed=reviewed)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(self.remote_ref("refs/heads/main"), reviewed)
        self.assertEqual(self.remote_ref(f"refs/tags/{self.tag()}^{{commit}}"), reviewed)
        self.assertEqual(self.git("status", "--porcelain", "--untracked-files=all"), "")   # nothing written into the checkout

    def commit_file(self, rel, text):
        open(os.path.join(self.repo, rel), "w").write(text); self.git("add", "-A"); self.git("commit", "-qm", "edit " + rel)

    def bump_docs(self, version, docs=VERSIONED_DOCS):
        for rel in docs:
            p = os.path.join(self.repo, rel)
            text = open(p).read()
            open(p, "w").write(text.replace(real_version(), version))

    def test_claude1_a_version_bump_without_the_setup_skill_stops(self):
        """Claude review 1 (3): the tag came from VERSION, but the setup skill still said "prints 0.7.1" and installed v0.7.1, so
        after a bump every computer reinstalled the release from before the scanner lock (or failed COMMIT CHECK)."""
        for left in VERSIONED_DOCS:
            with self.subTest(left=left):
                self.git("reset", "-q", "--hard", self.git("rev-list", "--max-parents=0", "HEAD"))
                self.bump_docs("0.7.2", [d for d in VERSIONED_DOCS if d != left])
                self.commit_file("watchtower/wt.py", 'VERSION = "0.7.2"\n')
                main = self.remote_ref("refs/heads/main")
                r, gh = self.publish()
                self.stopped(r, gh, main, f"STOPPED: {left} line ")
                self.assertIn(f"says {real_version()}", r.stdout)

    def test_batch3_the_tag_comes_from_wt_version(self):
        """Batch 3 (docs drift): publish.sh hardcoded v0.7.1, so a new release would have been tagged with the old number."""
        self.bump_docs("0.7.2")                                                        # Claude review 1 (3): a bump moves these too
        self.commit_file("watchtower/wt.py", 'import os\nVERSION = "0.7.2"\n')
        r, _ = self.publish()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(self.remote_ref("refs/tags/v0.7.2^{commit}"), self.git("rev-parse", "HEAD"))
        self.assertIn("Publishing ownerx/grokbot-watchtower v0.7.2 at", r.stdout)

    def test_batch3_no_version_line_stops(self):
        self.commit_file("watchtower/wt.py", "# no version here\n")
        main = self.remote_ref("refs/heads/main")
        r, gh = self.publish()
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("can't read VERSION from watchtower/wt.py", r.stdout)
        self.assertEqual(self.remote_ref("refs/heads/main"), main)                     # nothing pushed
        self.assertEqual(subprocess.run(["git", "--git-dir", self.remote, "tag"], capture_output=True, text=True).stdout.strip(), "")
        self.assertEqual(gh, "")

    def test_batch3_a_lock_missing_a_scanner_stops(self):
        """Batch 3 (R7): a release without a checksum for every scanner would leave that scanner unrun on every computer."""
        lock = "".join(l for l in open(os.path.join(self.repo, "scripts", "scanner-bins.lock")) if "  husk  " not in l)
        self.commit_file("scripts/scanner-bins.lock", "# header\n" + lock)
        main = self.remote_ref("refs/heads/main")
        r, gh = self.publish()
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("STOPPED: scripts/scanner-bins.lock has no checksum for husk", r.stdout)
        self.assertEqual(self.remote_ref("refs/heads/main"), main)
        self.assertIsNone(self.remote_ref(f"refs/tags/{self.tag()}"))
        self.assertEqual(gh, "")

    def stopped(self, r, gh, main, text):
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn(text, r.stdout)
        self.assertEqual(self.remote_ref("refs/heads/main"), main)                     # nothing pushed
        self.assertEqual(subprocess.run(["git", "--git-dir", self.remote, "tag"], capture_output=True, text=True).stdout.strip(), "")
        self.assertEqual(gh, "")

    def test_batch3_round1_lock_lines_watchtower_would_skip_stop(self):
        """Codex, batch 3 round 1 (7): six `<sha256>  <name>  ` lines with no architecture passed publish.sh's grep, while
        Watchtower's reader skipped every one: an empty lock, and no scanner would run on any computer."""
        self.commit_file("scripts/scanner-bins.lock", "".join(f"{hashlib.sha256(n.encode()).hexdigest()}  {n}  \n" for n in SCANNER_NAMES))
        main = self.remote_ref("refs/heads/main")
        r, gh = self.publish()
        self.stopped(r, gh, main, "STOPPED: scripts/scanner-bins.lock line 1 isn't `<sha256>  <name>  <arch>  <note>`")

    def test_batch3_round1_a_lock_with_only_arm64_lines_stops(self):
        self.commit_file("scripts/scanner-bins.lock", "".join(f"{hashlib.sha256(n.encode()).hexdigest()}  {n}  aarch64  test\n" for n in SCANNER_NAMES))
        main = self.remote_ref("refs/heads/main")
        r, gh = self.publish()
        self.stopped(r, gh, main, "STOPPED: scripts/scanner-bins.lock has no checksum for skillspector on x86_64 (or any)")

    def test_batch3_round1_two_version_lines_stop(self):
        """Codex, batch 3 round 1 (11): `head -n 1` took 0.7.2 while Python reports the last assignment, 0.7.3."""
        self.commit_file("watchtower/wt.py", 'VERSION = "0.7.2"\nVERSION = "0.7.3"\n')
        main = self.remote_ref("refs/heads/main")
        r, gh = self.publish()
        self.stopped(r, gh, main, "can't read VERSION from watchtower/wt.py: it is set 2 times")

    def test_batch3_round2_a_second_version_in_other_syntax_stops(self):
        """Codex, batch 3 round 2 (14): the line count missed valid Python such as `(VERSION) = "0.7.3"`: publish.sh read
        0.7.2 while Python reports 0.7.3."""
        for second in ('(VERSION) = "0.7.3"\n', 'for VERSION in ("0.7.3",):\n    pass\n'):
            with self.subTest(second=second):
                self.commit_file("watchtower/wt.py", 'VERSION = "0.7.2"\n' + second)
                main = self.remote_ref("refs/heads/main")
                r, gh = self.publish()
                self.stopped(r, gh, main, "can't read VERSION from watchtower/wt.py: it is set 2 times")


if __name__ == "__main__":
    unittest.main()
