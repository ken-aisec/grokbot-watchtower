"""Hardening batch 3, Codex review round 1: replays for its findings. Each fails on the build commit (9f88738) unless its
docstring says it is a contrast. The publish.sh replays (findings 7 and 11) are in test_scripts.Publish (test_batch3_round1_*).
The replays for findings 4, 5, 6 and 9 test row 8 (platform lone changes), which moved to the harden/item8-wip branch.
Against 7cf8996 (the PR's base; Claude review 1, finding 8): 12 error, 2 fail, and test_13 passes (it reads test files only).
"""
import hashlib, importlib.util, os, sys, unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_boxes import SCANNERS, wt  # noqa: E402
from test_batch3_scanners import _Scanners  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REAL_PY = os.path.realpath(sys.executable)


def chain_root_owned(p):
    while True:
        st = os.lstat(p)
        if st.st_uid != 0 or st.st_mode & 0o022:
            return False
        if os.path.dirname(p) == p:
            return True
        p = os.path.dirname(p)


TRUSTED_PY = chain_root_owned(REAL_PY)


def script(path, body):
    with open(path, "w") as f:
        f.write(body)
    os.chmod(path, 0o755)
    return path


class SealedCopy(_Scanners):
    """Finding 1: tool() hashed the file, and run() then started whatever the path held by then."""

    def test_1_a_scanner_swapped_after_its_check_never_runs(self):
        log = os.path.join(self.tmp, "evil.log")
        self.lock_line("gitleaks")                                             # the release lists gitleaks for this computer
        p = self.put("gitleaks", "#!/bin/sh\necho good\n")
        self.assertEqual(wt.tool("gitleaks"), p)
        script(p + ".new", f"#!/bin/sh\necho evil >> {log}\n")
        os.replace(p + ".new", p)                                              # swapped in after the check
        code, out, err = wt.run([p, "version"], 10)
        self.assertFalse(os.path.exists(log))
        self.assertNotEqual(code, 0)
        self.assertEqual(wt.SCANNER_PROBLEMS.get("gitleaks", ("",))[0], "changed")
        script(p + ".new", "#!/bin/sh\necho good\n")
        os.replace(p + ".new", p)                                              # and swapped back: still not trusted this run
        self.assertIsNone(wt.tool("gitleaks"))
        self.assertEqual([os.path.basename(f["where"]) for f in wt.scanner_x005()], ["gitleaks"])

    def test_1_contrast_the_checked_program_runs(self):
        """Contrast: passes on the build commit too."""
        p = self.put("gitleaks", "#!/bin/sh\necho good \"$1\"\n")
        self.assertEqual(wt.tool("gitleaks"), p)
        self.assertEqual(wt.run([p, "version"], 10)[:2], (0, "good version\n"))

    @unittest.skipUnless(TRUSTED_PY, "needs a root-owned Python")
    def test_1_a_venv_python_link_swapped_after_the_check_never_runs(self):
        os.makedirs(self.bin, exist_ok=True)
        link = os.path.join(self.bin, "python3")
        os.symlink(REAL_PY, link)
        p = self.put("pip-audit", f"#!{link}\nimport sys\nprint('ok', sys.prefix == sys.base_prefix, sys.argv[1:])\n")
        self.assertEqual(wt.tool("pip-audit"), p)
        code, out, _ = wt.run([p, "-r", "x"], 30)
        self.assertEqual((code, out.split()[0], out.split()[-1]), (0, "ok", "'x']"), out)    # runs as the pinned Python
        log = os.path.join(self.tmp, "evil.log")
        evil = script(os.path.join(self.tmp, "evil-python"), f"#!/bin/sh\necho evil >> {log}\nexec {REAL_PY} \"$@\"\n")
        os.remove(link); os.symlink(evil, link)                                # the link now leads to another program
        code, out, err = wt.run([p, "-r", "x"], 30)
        self.assertFalse(os.path.exists(log))
        self.assertNotEqual(code, 0)


class InterpreterTrust(_Scanners):
    """Finding 2: a Python outside Watchtower passed when it and its folder were chmod 0555, even though the Bot owned both."""

    def entry_point(self, target):
        os.makedirs(self.bin, exist_ok=True)
        for n in ("python3", "python"):
            os.symlink(target, os.path.join(self.bin, n))
        return self.put("pip-audit", f"#!{os.path.join(self.bin, 'python3')}\nimport sys\nprint('{{\"dependencies\": []}}')\n")

    @unittest.skipIf(os.getuid() == 0, "root can write anything")
    def test_2_a_read_only_python_the_bot_owns_is_not_trusted(self):
        d = os.path.join(self.tmp, "py"); os.makedirs(d)
        evil = script(os.path.join(d, "python3"), f"#!/bin/sh\nexec {REAL_PY} \"$@\"\n")
        os.chmod(evil, 0o555); os.chmod(d, 0o555)                              # Box's tearDown makes it removable again
        self.entry_point(evil)
        self.assertIsNone(wt.tool("pip-audit"))
        self.assertIsNone(wt.scanners_python())
        self.assertIn("Python it runs with", wt.SCANNER_PROBLEMS["pip-audit"][1])

    def test_2_only_the_python_watchtower_runs_under(self):
        other = os.path.realpath("/bin/sh")                                    # root-owned, but not Watchtower's Python
        self.entry_point(other)
        self.assertIsNone(wt.tool("pip-audit"))
        self.assertIsNone(wt.scanners_python())

    def test_2_every_folder_above_it_counts(self):
        fn = getattr(wt, "trusted_interpreter", None)
        self.assertTrue(callable(fn))
        self.assertIsNone(fn(os.path.join(self.tmp, "no-such-python")))
        copy = script(os.path.join(self.tmp, "python3"), "#!/bin/sh\n")
        self.assertIsNone(fn(copy))
        if TRUSTED_PY:
            self.assertEqual(fn(sys.executable), REAL_PY)


class ExpectedScanners(_Scanners):
    def test_3_a_scanner_first_used_while_another_is_missing_is_still_expected(self):
        """Finding 3: SkillSpector goes, OSV-Scanner arrives and runs, then OSV-Scanner goes. Its second absent run treated it as
        never installed and dropped its WT-D002 lines."""
        self.skills(1); self.project()
        self.engines()
        os.remove(os.path.join(self.bin, "osv-scanner"))
        self.audit()
        os.remove(os.path.join(self.bin, "skillspector"))
        self.put("osv-scanner", SCANNERS["osv-scanner"])
        self.audit()
        d2 = self.rules("WT-D002")
        self.assertTrue(d2)
        os.remove(os.path.join(self.bin, "osv-scanner"))
        self.audit()
        r = self.audit()
        self.assertEqual(self.rules("WT-D002"), d2)
        self.assertFalse([f for f in r["fixed"] if f["rule"] == "WT-D002"])
        self.assertIn("OSV-Scanner", r.get("scanners_missing", []))


class OwnToolsPython(_Scanners):
    def test_8_a_refused_scanner_python_keeps_the_last_w001_lines(self):
        """Finding 8: a missing or refused scanner Python returned before the stage was marked failed, so last run's WT-W001
        lines read as fixed."""
        self.skills(1); self.engines()
        self.audit()
        snap = wt.load_json(wt.state_path("last_findings.json"), {})
        w1 = wt.finding("WT-W001", "Watchtower's own tool urllib3 1.0 has known holes", "medium", ["ASI04", "AST02"],
                        "watchtower scanner package urllib3", "1 known: GHSA-test", "Tell Watchtower \"update yourself\".", source="pip-audit")
        snap["findings"].append(w1)
        wt.save_json(wt.state_path("last_findings.json"), snap)
        os.symlink(script(os.path.join(self.tmp, "python-anyone-can-edit"), f"#!/bin/sh\nexec {REAL_PY} \"$@\"\n"),
                   os.path.join(self.bin, "python"))
        r = self.audit()
        self.assertIn(w1["key"], [f["key"] for f in self.snap()["findings"]])
        self.assertFalse([f for f in r["fixed"] if f["rule"] == "WT-W001"])
        self.assertIn("Watchtower's own tools", r.get("stages_skipped", []))

    def test_8_contrast_no_scanner_python_ever_is_a_plain_skip(self):
        """Contrast: passes on the build commit too."""
        self.skills(1); self.engines()
        r = self.audit()
        self.assertNotIn("Watchtower's own tools", r.get("stages_skipped", []))


class BoundedHashing(_Scanners):
    """Finding 10: the whole file was read into memory before the lock was even consulted."""

    def test_10_a_program_with_no_lock_line_is_not_read(self):
        self.put("gitleaks", "#!/bin/sh\n", register=False)
        with mock.patch.object(wt, "scanner_digest", side_effect=AssertionError("read")), \
                mock.patch.object(hashlib, "sha256", side_effect=AssertionError("hashed")):
            self.assertIsNone(wt.tool("gitleaks"))
        self.assertEqual(wt.SCANNER_PROBLEMS["gitleaks"][0], "unlisted")

    def test_10_a_program_over_the_size_limit_is_refused_unread(self):
        p = self.put("gitleaks", "#!/bin/sh\n" + "#" * 8192 + "\n", register=False)
        self.lock_line("gitleaks", hashlib.sha256(open(p, "rb").read()).hexdigest())
        with mock.patch.object(wt, "SCANNER_MAX_BYTES", 4096, create=True):
            self.assertIsNone(wt.tool("gitleaks"))
            self.assertIn("too large", wt.SCANNER_PROBLEMS["gitleaks"][1])
            self.assertEqual(wt.run([p], 10)[0], 126)


class LockReader(_Scanners):
    def test_7_runtime_and_publish_read_the_lock_the_same_way(self):
        """Finding 7, the runtime half: publish.sh and Watchtower now share one reader. On the build commit scripts/scanner_lock.py
        doesn't exist, so this errors there; its runtime reader already skipped these lines (contrast for that half). The replay
        that fails on the build commit is test_scripts.Publish.test_batch3_round1_lock_lines_watchtower_would_skip_stop."""
        spec = importlib.util.spec_from_file_location("scanner_lock_t", os.path.join(ROOT, "scripts", "scanner_lock.py"))
        mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
        names = sorted(wt.SCANNER_NAMES)
        bad = "".join(f"{hashlib.sha256(n.encode()).hexdigest()}  {n}  \n" for n in names)
        good = "# header\n" + "".join(f"{hashlib.sha256(n.encode()).hexdigest()}  {n}  x86_64  v1\n" for n in names)
        for text, usable in ((bad, False), (good, True)):
            with open(self.lock, "w") as f:
                f.write(text)
            got = {n for (n, a) in wt.scanner_lock()} if wt.scanner_lock() else set()
            self.assertEqual(not mod.release_problems(text), usable)
            self.assertEqual(got == set(names), usable)


class Docs(unittest.TestCase):
    def read(self, *rel):
        with open(os.path.join(ROOT, *rel)) as f:
            return f.read()

    def test_12_daily_routine_reports_findings_before_any_scanner_retry(self):
        t = self.read("routines", "daily-watch.md")
        self.assertIn("JSON with `scanners_missing`", t)
        self.assertIn("never held back for a retry", t)

    def test_14_codescan_and_wt_describe_the_checked_folder(self):
        skill = self.read("skills", "watchtower-codescan", "SKILL.md")
        self.assertNotIn("if it's installed", skill)
        self.assertIn("checked scanner folder", skill)
        self.assertNotIn("are used when on PATH", wt.__doc__)
        self.assertIn("scanner-bins.lock", wt.__doc__)

    def test_13_contrasts_are_marked(self):
        """Finding 13 (test accounting): fails with the build commit's test files, which didn't mark these as contrasts."""
        import test_scripts, test_batch3_selfcheck_docs as docs
        for fn in (test_scripts.InstallScanners.test_batch3_a_failed_download_keeps_the_old_copy,
                   docs.VersionAfterTheSelfCheck.test_a_developer_checkout_prints_its_version):
            self.assertTrue((fn.__doc__ or "").startswith("Contrast"), fn.__name__)


if __name__ == "__main__":
    unittest.main()
