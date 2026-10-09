"""install.sh and publish.sh, run for real with stand-ins for pip, curl and gh. Nothing here reaches the network or GitHub."""
import hashlib, io, os, platform, shutil, subprocess, sys, tarfile, tempfile, unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
REAL_PY = shutil.which("python3") or sys.executable
GIT_ENV = {"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid", "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid",
           "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1", "GIT_TERMINAL_PROMPT": "0"}


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
        return sorted(f for f in ("gitleaks", "trufflehog", "osv-scanner") if os.access(os.path.join(self.wt, "bin", f), os.X_OK))

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


class Publish(unittest.TestCase):
    """publish.sh offered to force-push over GitHub's main, moved tags with `tag -f` / `push -f`, and made a private repo public."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.repo = os.path.join(self.tmp, "repo"); self.remote = os.path.join(self.tmp, "remote.git"); self.bin = os.path.join(self.tmp, "bin")
        self.ghlog = os.path.join(self.tmp, "gh.log")
        for d in ("scripts", "tests", "bot"):
            os.makedirs(os.path.join(self.repo, d))
        os.makedirs(self.bin)
        shutil.copy(os.path.join(ROOT, "scripts", "publish.sh"), os.path.join(self.repo, "scripts"))
        open(os.path.join(self.repo, "scripts", "make-manifest.sh"), "w").write("#!/bin/bash\necho manifest > MANIFEST.sha256\n")
        open(os.path.join(self.repo, "tests", "test_ok.py"), "w").write("import unittest\nclass T(unittest.TestCase):\n    def test_ok(self):\n        pass\n")
        open(os.path.join(self.repo, "bot", "memories.md"), "w").write("1. Install {TAG} at {COMMIT}.\n")
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

    def publish(self, vis="PUBLIC"):
        e = dict(os.environ, PATH=self.bin + ":" + os.environ["PATH"], GHLOG=self.ghlog, FAKE_VIS=vis, **GIT_ENV)
        r = subprocess.run(["bash", "scripts/publish.sh"], cwd=self.repo, env=e, input="yes\n", capture_output=True, text=True, timeout=120)
        return r, (open(self.ghlog).read() if os.path.exists(self.ghlog) else "")

    def tag(self):
        return open(os.path.join(ROOT, "scripts", "publish.sh")).read().split('TAG="')[1].split('"')[0]

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


if __name__ == "__main__":
    unittest.main()
