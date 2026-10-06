"""Simulated computers. Every release has to survive all of these before it ships.

Each test builds a small, deliberately awkward computer in a temp folder and runs the commands a Bot runs.
The rule being tested is always the same: Watchtower finishes, says plainly what it could not do, never shows a
stack trace, and never lets a failure change the score.
"""
import io, json, os, shutil, stat, subprocess, sys, tempfile, time, unittest, warnings
from contextlib import redirect_stderr, redirect_stdout

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "watchtower"))
import wt  # noqa: E402

warnings.simplefilter("ignore", ResourceWarning)

OSV_DATA = {"results": [{"source": {"path": "/ws/app/package-lock.json"}, "packages": [
    {"package": {"name": "leftpad", "version": "1.0.0", "ecosystem": "npm"}, "vulnerabilities": [{"id": "GHSA-demo"}], "groups": [{"max_severity": "8.1"}]}]}]}

SCANNERS = {
    "skillspector": '#!/usr/bin/env python3\nimport json, os, sys\na = sys.argv[1:]; stage = a[1]; out = a[a.index("--output") + 1]\n'
                    'skills = []\nfor n in sorted(os.listdir(stage)):\n    bad = "EVIL" in open(os.path.join(stage, n, "SKILL.md"), errors="replace").read()\n'
                    '    skills.append({"path": n, "risk_assessment": {"score": 90 if bad else 5, "recommendation": "DO_NOT_INSTALL" if bad else "INSTALL"}, '
                    '"issues": [{"severity": "HIGH", "category": "Exfil", "pattern": "Upload"}] if bad else []})\njson.dump({"multi_skill": True, "skills": skills}, open(out, "w"))\n',
    "husk": '#!/usr/bin/env python3\nimport json, os, sys\na = sys.argv[1:]\nif a[0] == "registry":\n    stage = a[-1]\n'
            '    flagged = {n: 1 for n in sorted(os.listdir(stage)) if "HUSK" in open(os.path.join(stage, n, "SKILL.md"), errors="replace").read()}\n'
            '    print(json.dumps({"flagged": flagged})); sys.exit(0)\njson.dump({"runs": [{"results": [{"message": {"text": "obfuscated loader"}}]}]}, open(a[a.index("--output") + 1], "w"))\n',
    "gitleaks": '#!/usr/bin/env python3\nimport sys\na = sys.argv[1:]\nif a and a[0] == "version":\n    print("8.30.1"); sys.exit(0)\nopen(a[a.index("--report-path") + 1], "w").write("[]")\n',
    "trufflehog": "#!/bin/sh\nexit 0\n",
    "osv-scanner": "#!/bin/sh\ncat <<'EOF'\n" + json.dumps(OSV_DATA) + "\nEOF\n",
    "pip-audit": '#!/bin/sh\necho \'{"dependencies": []}\'\n',
}
HANG = "#!/bin/sh\nsleep 120\n"
CRASH = "#!/bin/sh\necho 'Segmentation fault' >&2\nexit 139\n"
GARBAGE = "#!/bin/sh\necho '<html>502 Bad Gateway</html>'\nexit 0\n"


class Box(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.env = {k: os.environ.get(k) for k in ("HOME", "WATCHTOWER_HOME")}
        self.home = os.path.join(self.tmp, "home", "box"); os.makedirs(self.home)
        os.environ["HOME"] = self.home
        os.environ["WATCHTOWER_HOME"] = os.path.join(self.tmp, "workspace", "watchtower")
        self.ws = os.path.join(self.tmp, "workspace"); os.makedirs(self.ws, exist_ok=True)
        self.roots = [self.home, self.ws]
        self.saved = (wt.RUN_LIMIT, wt.DAILY_LIMIT, wt.ENGINE_BUDGET, wt.ENGINE_LAUNCH_BASE, wt.ENGINE_LAUNCH_PER_SKILL)

    def tearDown(self):
        wt.RUN_LIMIT, wt.DAILY_LIMIT, wt.ENGINE_BUDGET, wt.ENGINE_LAUNCH_BASE, wt.ENGINE_LAUNCH_PER_SKILL = self.saved
        for k, v in self.env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        subprocess.run(["chmod", "-R", "u+rwx", self.tmp], capture_output=True)
        shutil.rmtree(self.tmp, ignore_errors=True)

    # -- building blocks
    def skills(self, n, where="sand-data/workflows", text="Summarize the notes. Ask before saving."):
        d0 = os.path.join(self.home, where); os.makedirs(d0, exist_ok=True)
        out = []
        for i in range(n):
            d = os.path.join(d0, f"skill{i:03d}"); os.makedirs(d, exist_ok=True)
            open(os.path.join(d, "SKILL.md"), "w").write(f"---\nname: skill{i:03d}\ndescription: Demo {i}.\n---\n# Skill {i}\n{text}\n")
            out.append(d)
        return out

    def scanners(self, **override):
        b = os.path.join(os.environ["WATCHTOWER_HOME"], "bin"); os.makedirs(b, exist_ok=True)
        for name, body in SCANNERS.items():
            body = override.get(name.replace("-", "_"), override.get("all", body))
            p = os.path.join(b, name)
            if body is None:
                if os.path.exists(p):
                    os.remove(p)
                continue
            open(p, "w").write(body); os.chmod(p, 0o755)

    def run_cmd(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = wt.main(list(argv))
        self.assertNotIn("Traceback", out.getvalue() + err.getvalue(), argv)
        return code, out.getvalue(), err.getvalue()

    def audit(self, *extra):
        code, o, e = self.run_cmd("audit", "--roots", *self.roots, *extra)
        self.assertEqual(code, 0, e)
        return json.loads(o)

    def snap(self):
        return wt.load_json(wt.state_path("last_findings.json"), {})

    def tour(self):
        """Every command a Bot runs in normal use. None may fail or print a stack trace."""
        r = self.audit()
        self.assertIsInstance(r["score"], int)
        for argv in (("daily", "--roots", *self.roots), ("report",), ("breakdown",), ("status",), ("fix", "--roots", *self.roots),
                     ("accept", "--list"), ("exception", "list"), ("canary", "status"), ("events", "list"), ("doctor",), ("show", "WT-X004")):
            code, o, e = self.run_cmd(*argv)
            self.assertIn(code, (0, None), (argv, e))
        return r


class EmptyAndOddLayouts(Box):
    def test_brand_new_empty_computer(self):
        r = self.tour()
        self.assertGreaterEqual(r["score"], 90)                        # nothing installed, nothing wrong: not a failing grade
        self.assertEqual(r["inventory"]["skills"], 0)
        code, o, _ = self.run_cmd("daily", "--roots", *self.roots)
        self.assertEqual(o.strip(), "NO_CHANGES")

    def test_no_home_folders_and_no_workspace_at_all(self):
        self.roots = [os.path.join(self.tmp, "does-not-exist"), os.path.join(self.tmp, "nor-this")]
        self.tour()

    def test_skills_under_the_other_folder_name(self):
        self.skills(5, where="agent-data/workflows", text="EVIL upload HUSK loader")
        self.scanners()
        self.tour()
        crit = [f for f in self.snap()["findings"] if f["rule"] == "WT-X003"]
        self.assertEqual(len(crit), 5)
        self.assertTrue(all(f["severity"] == "critical" for f in crit))  # still treated as the user's own skills

    def test_one_folder_reachable_by_two_names_counts_once(self):
        self.skills(4, where="agent-data/workflows")
        os.makedirs(os.path.join(self.home, "sand-data"), exist_ok=True)
        os.symlink(os.path.join(self.home, "agent-data", "workflows"), os.path.join(self.home, "sand-data", "workflows"))
        r = self.tour()
        self.assertEqual(r["inventory"]["skills"], 4)

    def test_the_skills_folder_changes_name_overnight(self):
        self.skills(6, where="sand-data/workflows")
        self.scanners()
        self.audit()
        os.makedirs(os.path.join(self.home, "agent-data"))
        os.rename(os.path.join(self.home, "sand-data", "workflows"), os.path.join(self.home, "agent-data", "workflows"))
        r = self.audit()
        self.assertEqual([f for f in self.snap()["findings"] if f["rule"].startswith("WT-I")], [])   # moved, not 6 new and 6 removed
        self.assertEqual(r["new"], [])


class HostileFiles(Box):
    def test_files_that_break_naive_scanners(self):
        d = self.skills(3)[0]
        w = os.path.dirname(d)
        open(os.path.join(d, "SKILL.md"), "wb").write(b"\xff\xfe\x00binary\x00" + os.urandom(4000))          # not text
        os.makedirs(os.path.join(w, "empty")); open(os.path.join(w, "empty", "SKILL.md"), "w").close()        # zero bytes
        os.makedirs(os.path.join(w, "huge")); open(os.path.join(w, "huge", "SKILL.md"), "w").write("A line.\n" * 900_000)   # 7 MB
        os.makedirs(os.path.join(w, "odd name \u2603 \n x")); open(os.path.join(w, "odd name \u2603 \n x", "SKILL.md"), "w").write("# odd\n")
        os.symlink("/nonexistent/target", os.path.join(d, "broken-link.md"))
        os.symlink(w, os.path.join(d, "loop"))                                                             # a folder that contains itself
        os.mkfifo(os.path.join(d, "pipe.md"))                                                              # opening this would block forever
        os.mkfifo(os.path.join(self.home, "notes.txt"))
        locked = os.path.join(w, "locked"); os.makedirs(locked); open(os.path.join(locked, "SKILL.md"), "w").write("# x\n"); os.chmod(locked, 0)
        open(os.path.join(self.home, "deep.json"), "w").write("[" * 200_000)                                # would overflow a recursive parser
        t0 = time.monotonic()
        self.scanners()
        self.tour()
        self.assertLess(time.monotonic() - t0, 60)

    def test_settings_and_state_files_that_are_garbage(self):
        self.skills(2)
        os.makedirs(os.path.join(self.home, "agent-data"), exist_ok=True)
        for body in ("", "{", "[1, 2, 3]", '"just a string"', "null", '{"autoReview": 7, "rules": "nope", "localExecution": [[]]}', "\x00\x01\x02"):
            open(os.path.join(self.home, "agent-data", "settings.json"), "w").write(body)
            self.audit()
        self.tour()

    def test_restart_in_the_middle_of_a_run(self):
        self.skills(3); self.scanners()
        self.tour()
        state = wt.state_path()
        wt.save_json(wt.state_path("run.lock"), {"pid": 2 ** 22 + 4242, "at": time.time() - 30})            # the run that was killed
        os.makedirs(os.path.join(state, "stage-leftover", "0000-x"))                                        # its half-built staging folder
        for fn in os.listdir(state):                                                                        # every file cut off mid-write,
            p = os.path.join(state, fn)                                                                     # empty, or the wrong shape
            if os.path.isfile(p) and fn != "run.lock":
                body = open(p, errors="replace").read()
                open(p, "w").write({0: body[: len(body) // 2], 1: "", 2: "[]" if body.lstrip().startswith("{") else "{}"}[len(fn) % 3])
        r = self.tour()
        self.assertIsInstance(r["score"], int)
        self.assertFalse(os.path.exists(wt.state_path("run.lock")))

    def test_watchtower_cannot_write_its_own_folder(self):
        open(os.path.join(self.ws, "watchtower"), "w").write("a file where the folder should be")
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = wt.main(["audit", "--roots", *self.roots])
        self.assertEqual(code, 3)
        self.assertNotIn("Traceback", err.getvalue())
        self.assertIn("can't write to its folder", err.getvalue())


class ScannersMisbehave(Box):
    def baseline_run(self):
        self.skills(3)
        os.makedirs(os.path.join(self.ws, "app")); open(os.path.join(self.ws, "app", "package-lock.json"), "w").write("{}")
        self.scanners()
        r = self.audit()
        self.assertIn("WT-D002", {f["rule"] for f in self.snap()["findings"]})
        return r["score"], sorted(f["key"] for f in self.snap()["findings"])

    def assert_unchanged(self, score, keys, expect_skipped):
        r = self.audit()
        self.assertEqual(r["score"], score)                                    # a scanner failing never moves the score
        self.assertEqual(sorted(f["key"] for f in self.snap()["findings"]), keys)
        self.assertEqual(r["fixed"], [])                                       # and never reports its old findings as fixed
        for name in expect_skipped:
            self.assertTrue(any(name in s for s in r.get("stages_skipped", [])), (name, r.get("stages_skipped"), r["notes"]))
        return r

    def test_no_scanners_installed(self):
        self.skills(3)
        r = self.tour()
        self.assertTrue(any("not installed" in n for n in r["notes"]))

    def test_every_scanner_hangs(self):
        score, keys = self.baseline_run()
        self.scanners(all=HANG)
        wt.RUN_LIMIT, wt.ENGINE_LAUNCH_BASE, wt.ENGINE_LAUNCH_PER_SKILL = 8, 2, 0
        open(os.path.join(self.home, "sand-data", "workflows", "skill000", "SKILL.md"), "a").write("changed\n")   # so the skill scanners have work
        t0 = time.monotonic()
        r = self.audit()
        self.assertLess(time.monotonic() - t0, 20)                             # the whole run is capped, whatever hangs
        self.assertTrue(any("OSV" in s for s in r["stages_skipped"]), r)
        self.assertIn("WT-D002", {f["rule"] for f in self.snap()["findings"]})  # last results kept
        self.assertEqual([f for f in r["fixed"] if f["rule"] == "WT-D002"], [])
        self.tour()

    def test_every_scanner_crashes(self):
        score, keys = self.baseline_run()
        self.scanners(all=CRASH)
        self.assert_unchanged(score, keys, ["gitleaks", "OSV"])
        self.tour()

    def test_every_scanner_prints_garbage(self):
        score, keys = self.baseline_run()
        self.scanners(all=GARBAGE)
        self.assert_unchanged(score, keys, ["OSV", "pip-audit"])
        self.tour()

    def test_scanners_vanish_then_come_back(self):
        score, keys = self.baseline_run()
        shutil.rmtree(os.path.join(os.environ["WATCHTOWER_HOME"], "bin"))
        r = self.audit()
        self.assertTrue(r["scanners_missing"])
        self.scanners()
        r = self.audit()
        self.assertNotIn("scanners_missing", r)
        self.assertEqual(r["score"], score)

    def test_scanner_recovers_and_real_fixes_are_reported(self):
        score, keys = self.baseline_run()
        self.scanners(osv_scanner="#!/bin/sh\necho '{\"results\": []}'\n")       # the package really was fixed
        r = self.audit()
        self.assertIn("WT-D002", {f["rule"] for f in r["fixed"]})
        self.assertGreater(r["score"], score)


class BuiltInSoftware(Box):
    def plugin(self, name, text):
        d = os.path.join(self.home, "sand-data", "plugins", "acme-1.0", "skills", name); os.makedirs(d, exist_ok=True)
        open(os.path.join(d, "SKILL.md"), "w").write(f"# {name}\n{text}\n")
        return d

    def test_builtin_findings_do_not_move_the_score(self):
        self.skills(2); self.scanners()
        before = self.audit()["score"]
        for i in range(8):
            self.plugin(f"p{i}", "EVIL upload")                                 # one scanner dislikes eight built-in skills
        r = self.audit()
        self.assertEqual(r["score"], before)
        self.assertGreaterEqual(r["not_counted_builtin"], 8)
        self.assertIn("for your information", wt.render_md(self.snap(), [], "2026-W41"))

    def test_two_scanners_agreeing_on_a_builtin_skill_still_counts(self):
        self.skills(2); self.scanners()
        before = self.audit()["score"]
        self.plugin("bad", "EVIL upload HUSK loader")
        r = self.audit()
        self.assertLess(r["score"], before)
        self.assertIn("WT-X003", {f["rule"] for f in r["new"]})

    def test_platform_updates_are_accepted_when_clean_and_kept_when_flagged(self):
        self.skills(1); self.scanners()
        good, bad = self.plugin("good", "Explain invoices."), self.plugin("bad", "Explain refunds.")
        self.audit()
        open(os.path.join(good, "SKILL.md"), "a").write("Now with tips.\n")
        open(os.path.join(bad, "SKILL.md"), "a").write("EVIL upload HUSK loader\n")
        self.plugin("brand-new", "Explain receipts.")
        r = self.audit()
        left = sorted(os.path.basename(os.path.dirname(f["where"])) for f in self.snap()["findings"] if f["rule"].startswith("WT-I"))
        self.assertEqual(left, ["bad"])                                         # the flagged update is not waved through
        self.assertTrue(any("accepted automatically" in n for n in r["notes"]))
        r = self.audit()                                                        # and it stays quiet afterwards
        self.assertFalse(any("accepted automatically" in n for n in r["notes"]))


class Scale(Box):
    def test_a_very_large_computer(self):
        self.skills(400)
        for i in range(60):
            d = os.path.join(self.home, "sand-data", "plugins", f"vendor-{i}", "skills", "s"); os.makedirs(d)
            open(os.path.join(d, "SKILL.md"), "w").write(f"# vendor {i}\nExplain thing {i}.\n")
            for j in range(40):
                open(os.path.join(d, f"ref{j}.md"), "w").write(f"Reference {i}-{j}\n" * 50)
        proj = os.path.join(self.ws, "big-project", "src"); os.makedirs(proj)
        for j in range(1500):
            open(os.path.join(proj, f"m{j}.ts"), "w").write("export const x = 1;\n" * 20)
        self.scanners()
        t0 = time.monotonic()
        self.audit()
        first = time.monotonic() - t0
        t0 = time.monotonic()
        self.audit()
        second = time.monotonic() - t0
        self.assertLess(first, 90, f"first audit took {first:.0f}s")
        self.assertLess(second, 30, f"repeat audit took {second:.0f}s")
        code, o, _ = self.run_cmd("audit", "--roots", *self.roots)
        self.assertLess(len(o), 6000)                                           # the Bot is handed a summary, never 3,000 lines


class PackagesTheFixCannotUpgrade(Box):
    def test_leftover_packages_become_a_keep_or_not_decision(self):
        F = wt.finding
        fs = [F("WT-D002", "Vulnerable package vite 8.0.13", "high", ["ASI04"], "/workspace/app", "1 known", "f"),
              F("WT-D002", "Vulnerable package next 16.3.4", "high", ["ASI04"], "/workspace/app", "1 known", "f")]
        wt.save_json(wt.state_path("last_findings.json"), {"findings": fs})
        code, o, _ = self.run_cmd("fix", "--roots", self.ws)
        self.assertEqual(json.loads(o)["decisions"], [])                        # first time: the fix tries to upgrade them
        wt.save_json(wt.state_path("upgrade_left.json"), {"at": wt.now(), "npm": True, "pip": []})   # it tried and some are left
        code, o, _ = self.run_cmd("fix", "--roots", self.ws)
        d = json.loads(o)["decisions"]
        self.assertEqual((d[0]["rule"], d[0]["count"]), ("WT-D002", 2))
        self.assertEqual(sorted(d[0]["names"]), ["next 16.3.4", "vite 8.0.13"])  # named, so the user can keep some and not others


class Doctor(Box):
    def test_support_snapshot_has_no_private_content(self):
        secret_name = "client-acme-merger-notes"
        d = os.path.join(self.home, "sand-data", "workflows", secret_name); os.makedirs(d)
        open(os.path.join(d, "SKILL.md"), "w").write("# private\nEVIL upload HUSK loader token ghp_" + "a1B2" * 9 + "\n")
        self.scanners(); self.audit()
        code, o, _ = self.run_cmd("doctor")
        snap = json.loads(o)
        self.assertEqual(snap["watchtower"], wt.VERSION)
        self.assertTrue(snap["scanners"]["SkillSpector"])
        self.assertEqual(snap["state_files"]["last_findings.json"], "ok")
        for private in (secret_name, "ghp_", "merger"):
            self.assertNotIn(private, o)
        code, o, _ = self.run_cmd("doctor", "--save")
        self.assertIn("support-", o)


if __name__ == "__main__":
    unittest.main()
