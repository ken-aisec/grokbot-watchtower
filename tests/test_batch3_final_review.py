"""Hardening batch 3, Codex final review of rows 12 and 5: replays for the semgrep high (wt.py:6874 on dd27c42) and the launch
deadline medium. Each fails on dd27c42 unless its docstring says it is a contrast. Against 7cf8996 (the PR's base; Claude
review 1, finding 8) all 9 error, the 3 contrasts too: the scanner code these tests drive isn't there.
"""
import json, os, sys, threading, time, unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_boxes import wt  # noqa: E402
from test_batch3_scanners import _Scanners  # noqa: E402

FOUND = ('#!/bin/sh\necho \'{"results": [{"check_id": "python.lang.security.sqli", "path": "app.py", "start": {"line": 2}, '
         '"extra": {"severity": "ERROR", "message": "SQL built from user input"}}]}\'\n')


def script(path, body):
    with open(path, "w") as f:
        f.write(body)
    os.chmod(path, 0o755)
    return path


class SemgrepInCodescan(_Scanners):
    """A semgrep that was refused at launch, changed, failed or printed no results said "semgrep found and used too", and a
    swapped copy raised nothing (only SCANNER_NAMES could be a WT-X005)."""

    def setUp(self):
        super().setUp()
        self.proj = os.path.join(self.ws, "app")
        os.makedirs(self.proj)
        with open(os.path.join(self.proj, "app.py"), "w") as f:
            f.write("import os\nprint(os.getcwd())\n")

    def listed(self, body):
        p = self.put("semgrep", body, register=False)
        self.lock_line("semgrep", wt.scanner_digest(p))                         # the lock lists this very copy
        wt._SCANNER_LOCK_CACHE.clear()
        return p

    def codescan(self):
        code, o, e = self.run_cmd("codescan", self.proj)
        self.assertEqual(code, 0, o + e)
        return json.loads(o)

    def x005(self, r):
        return [f for f in r["findings"] if f["rule"] == "WT-X005"]

    def test_a_semgrep_refused_at_launch_is_never_used_and_is_a_high_alert(self):
        log = os.path.join(self.tmp, "evil.log")
        p = self.listed(FOUND)
        real = wt.tool

        def tool_then_swap(name):                                               # checked, then swapped before it starts
            got = real(name)
            if name == "semgrep":
                os.replace(script(p + ".new", f"#!/bin/sh\necho evil >> {log}\necho '{{\"results\": []}}'\n"), p)
            return got
        with mock.patch.object(wt, "tool", tool_then_swap):
            r = self.codescan()
        self.assertFalse(os.path.exists(log))
        self.assertNotIn("found and used", r["engine"])
        self.assertIn("semgrep NOT run", r["engine"])
        self.assertTrue(r.get("not_checked_this_run"), r)
        x5 = self.x005(r)
        self.assertEqual([(f["severity"], os.path.basename(f["where"])) for f in x5], [("high", "semgrep")])
        self.assertNotIn("install.sh --scanners", x5[0]["fix"])                  # install.sh doesn't install semgrep

    def test_a_changed_semgrep_is_a_high_alert_not_just_missing(self):
        self.put("semgrep", FOUND, register=False)
        self.lock_line("semgrep")                                               # the lock lists another program
        wt._SCANNER_LOCK_CACHE.clear()
        r = self.codescan()
        self.assertIn("semgrep NOT run", r["engine"])
        self.assertTrue(r.get("not_checked_this_run"), r)
        self.assertEqual(len(self.x005(r)), 1)

    def test_a_semgrep_that_fails_or_prints_no_results_is_not_used(self):
        for body in ('#!/bin/sh\necho \'{"errors": [{"message": "rules not downloaded"}], "results": []}\'\nexit 2\n',
                     "#!/bin/sh\necho 'Killed' >&2\n",
                     "#!/bin/sh\necho '{\"errors\": []}'\n"):
            with self.subTest(body=body):
                wt.SCANNER_PROBLEMS.clear()
                with open(self.lock, "w") as f:
                    f.write("# test lock\n")
                self.listed(body)
                r = self.codescan()
                self.assertNotIn("found and used", r["engine"])
                self.assertIn("semgrep did NOT finish", r["engine"])
                self.assertTrue(r.get("not_checked_this_run"), r)
                self.assertEqual(self.x005(r), [])                              # a failed run is not a swapped copy

    def test_contrast_a_clean_semgrep_run_is_used(self):
        """Contrast: passes on dd27c42 too."""
        self.listed(FOUND)
        r = self.codescan()
        self.assertEqual(r["engine"], "semgrep found and used too")
        self.assertNotIn("not_checked_this_run", r)
        self.assertTrue([f for f in r["findings"] if f["rule"] == "WT-WSG"])

    def test_contrast_no_semgrep_is_a_plain_note(self):
        """Contrast: passes on dd27c42 too."""
        r = self.codescan()
        self.assertIn("semgrep isn't one of Watchtower's checked scanners", r["engine"])
        self.assertNotIn("not_checked_this_run", r)
        self.assertEqual(self.x005(r), [])


class LaunchDeadline(_Scanners):
    """run()'s timeout covered only the program itself and the time before its copy was made: waiting for another launch
    (_LAUNCH, held while the other engine's copy is made) had no limit, and making the copy had its own (SCANNER_HASH_SECONDS),
    so a 1-second call took as long as the other launch or the copy took."""

    def hold_launch(self, seconds):
        wt._LAUNCH.acquire()
        t = threading.Timer(seconds, wt._LAUNCH.release)
        t.start()
        self.addCleanup(t.join)

    def timed(self, cmd, timeout):
        t0 = time.monotonic()
        res = wt.run(cmd, timeout)
        return res, time.monotonic() - t0

    def test_waiting_for_another_launch_counts_against_a_scanners_timeout(self):
        p = self.put("gitleaks", "#!/bin/sh\necho done\n")
        self.hold_launch(3)
        (code, _, _), took = self.timed([p], 1)
        self.assertEqual(code, 124)
        self.assertLess(took, 2)
        self.assertNotIn("gitleaks", wt.SCANNER_PROBLEMS)                        # a time out, not a refusal

    def test_waiting_for_another_launch_counts_against_any_programs_timeout(self):
        self.hold_launch(3)
        (code, _, _), took = self.timed(["/bin/sh", "-c", "echo hi"], 1)
        self.assertEqual(code, 124)
        self.assertLess(took, 2)

    def test_making_the_copy_is_bounded_by_the_launch_deadline(self):
        p = self.put("gitleaks", "#!/bin/sh\necho done\n")
        real, calls = os.read, []

        def slow(fd, n):
            if not calls:
                calls.append(1)
                time.sleep(3)
            return real(fd, n)
        with mock.patch.object(wt.os, "read", slow):
            (code, _, _), took = self.timed([p], 1)
        for t in threading.enumerate():                                         # let the copy given up on finish and close
            if t.name == "watchtower-hash":
                t.join(10)
        self.assertEqual(code, 124)
        self.assertLess(took, 2)
        self.assertNotIn("gitleaks", wt.SCANNER_PROBLEMS)
        self.assertEqual(wt.run([p], 10)[:2], (0, "done\n"))                     # judged again at its next launch, and runs

    def test_contrast_a_launch_within_its_time_runs(self):
        """Contrast: passes on dd27c42 too."""
        p = self.put("gitleaks", "#!/bin/sh\necho done\n")
        self.hold_launch(0.5)
        (code, out, _), took = self.timed([p], 5)
        self.assertEqual((code, out), (0, "done\n"))


if __name__ == "__main__":
    unittest.main()
