"""Hardening batch 3, Codex review round 2: replays for its findings. Each fails on fix round 1 (55a4290) unless its docstring
says it is a contrast. The publish.sh replay (finding 14) is test_scripts.Publish.test_batch3_round2_*. Findings 3 to 9 and
11 (and the accounting check, 15) test row 8 (platform lone changes), which moved to the harden/item8-wip branch.
Against 7cf8996 (the PR's base; Claude review 1, finding 8) all 6 error.
"""
import hashlib, importlib.util, os, shutil, subprocess, sys, time, unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_boxes import wt  # noqa: E402
from test_batch3_scanners import _Scanners, arch  # noqa: E402
from test_batch3_fix_round1 import chain_root_owned  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
READER = os.path.join(ROOT, "scripts", "scanner_lock.py")


def reader():
    """scripts/scanner_lock.py from its source, without writing a bytecode cache into the checkout."""
    ns = {"__name__": "scanner_lock_t"}
    with open(READER, "rb") as f:
        exec(compile(f.read(), READER, "exec"), ns)
    return ns


def six_lines():
    return "".join(f"{hashlib.sha256(n.encode()).hexdigest()}  {n}  x86_64  v1\n" for n in sorted(wt.SCANNER_NAMES))


class CachedReader(_Scanners):
    def test_1_a_planted_bytecode_cache_never_replaces_the_lock_reader(self):
        """Finding 1: the reader was imported, so Python ran a scanner_lock.*.pyc with the source's mtime and size instead of the
        checked source, and its parse() decided which programs were scanners."""
        app = os.path.join(self.tmp, "app")
        os.makedirs(os.path.join(app, "watchtower")); os.makedirs(os.path.join(app, "scripts"))
        src = os.path.join(app, "scripts", "scanner_lock.py")
        shutil.copy(READER, src)
        forged = compile("def read_lock(p):\n    return '', None\n"
                         f"def parse(t):\n    return {{('gitleaks', 'any'): {{'{'f' * 64}'}}}}, []\n", src, "exec")
        st = os.stat(src)
        cache = importlib.util.cache_from_source(src)
        os.makedirs(os.path.dirname(cache))
        with open(cache, "wb") as f:
            f.write(importlib._bootstrap_external._code_to_timestamp_pyc(forged, int(st.st_mtime), st.st_size))
        self.lock_line("gitleaks", "a" * 64)
        wt._SCANNER_LOCK_CACHE.clear()
        try:
            with mock.patch.object(wt, "HERE", os.path.join(app, "watchtower")):
                lock = wt.scanner_lock()
        finally:
            wt._SCANNER_LOCK_CACHE.clear()
        self.assertNotIn(("gitleaks", "any"), lock)
        self.assertEqual(lock, {("gitleaks", arch()): {"a" * 64}})              # read by the checked source, from the lock file


class RunningInterpreter(_Scanners):
    @unittest.skipUnless(chain_root_owned(os.path.realpath("/bin/sh")), "needs a root-owned /bin/sh")
    def test_2_trust_follows_the_running_interpreter_not_its_launcher_name(self):
        """Finding 2: realpath(sys.executable) followed the link Watchtower was started through. With that link and the scanner
        Python link retargeted at another root-owned program, that program was the "pinned" Python."""
        other = os.path.realpath("/bin/sh")
        launcher = os.path.join(self.tmp, "venv-python")
        os.symlink(other, launcher)                                            # the launcher Watchtower started through, retargeted
        os.makedirs(self.bin, exist_ok=True)
        for n in ("python3", "python"):
            os.symlink(other, os.path.join(self.bin, n))
        with mock.patch.object(sys, "executable", launcher):
            self.assertIsNone(wt.trusted_interpreter(os.path.join(self.bin, "python3")))
            self.assertIsNone(wt.scanners_python())


class BoundedTime(_Scanners):
    def test_10_one_slow_read_is_bounded(self):
        """Finding 10: the deadline was checked only between reads, so one slow read followed by EOF took as long as it took."""
        p = self.put("gitleaks", "", register=False)
        wt.SCANNER_LOCK_EXTRA["gitleaks"] = hashlib.sha256(b"").hexdigest()
        real, calls = os.read, []

        def slow(fd, n):
            if not calls:
                calls.append(1)
                time.sleep(3)
                return b""
            return real(fd, n)
        with mock.patch.object(wt, "SCANNER_HASH_SECONDS", 1), mock.patch.object(wt.os, "read", slow):
            t0 = time.monotonic()
            got = wt.tool("gitleaks")
            took = time.monotonic() - t0
        self.assertIsNone(got, p)
        self.assertLess(took, 2.5)
        self.assertIn("too long", wt.SCANNER_PROBLEMS["gitleaks"][1])

    def test_10_making_the_sealed_copy_counts_against_the_programs_time(self):
        """Finding 10: run() set the program's timeout before the copy was made, so copying plus running took longer."""
        p = self.put("gitleaks", "#!/bin/sh\nsleep 1.5\necho done\n")
        real = wt._sealed_copy

        def slow_copy(path, *rest):                                             # rest: run()'s deadline (final review)
            time.sleep(1.5)
            return real(path, *rest)
        with mock.patch.object(wt, "_sealed_copy", slow_copy):
            t0 = time.monotonic()
            code, _, _ = wt.run([p], 2)
            took = time.monotonic() - t0
        self.assertEqual(code, 124)
        self.assertLess(took, 2.8)


class SharedLockRules(_Scanners):
    def test_12_publication_refuses_a_lock_the_runtime_refuses(self):
        """Finding 12: publication read the lock without the runtime's 1,000,000-byte limit, so a complete lock padded with
        comments passed publish.sh while Watchtower listed no scanner at all."""
        with open(self.lock, "w") as f:
            f.write(six_lines() + ("#" + "x" * 999 + "\n") * 1001)
        wt._SCANNER_LOCK_CACHE.clear()
        self.assertEqual(wt.scanner_lock(), {})                                  # the runtime refuses it whole (already on 55a4290)
        r = subprocess.run([sys.executable, "-I", READER, self.lock], capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("is over 1000000 bytes", r.stdout)

    def test_13_semgrep_may_be_listed_and_is_not_required(self):
        """Finding 13: semgrep wasn't a name the reader accepted, so codescan's optional semgrep could never be enabled, and a
        line for it stopped publication."""
        mod = reader()
        semgrep = f"{'a' * 64}  semgrep  x86_64  v1\n"
        lock, problems = mod["parse"](six_lines() + semgrep)
        self.assertEqual(problems, [])
        self.assertIn(("semgrep", "x86_64"), lock)
        self.assertEqual(mod["release_problems"](six_lines() + semgrep), [])
        self.assertEqual(mod["release_problems"](six_lines()), [])                # still optional
        p = self.put("semgrep", "#!/bin/sh\necho '{\"results\": []}'\n", register=False)
        self.lock_line("semgrep", wt.scanner_digest(p))
        wt._SCANNER_LOCK_CACHE.clear()
        self.assertEqual(wt.tool("semgrep"), p)


if __name__ == "__main__":
    unittest.main()
