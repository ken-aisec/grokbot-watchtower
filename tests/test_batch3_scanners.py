"""Hardening batch 3, roadmap row 5 (Oct 16 review R7: scanners).

tool() looked on PATH first, so any program named skillspector that a Bot put on PATH was run as Watchtower's second engine,
and a copy in Watchtower's own folder was run whatever its contents. A missing scanner counted as clean: its stage wasn't
marked failed, its old findings showed as "fixed" and the score rose; revet and the built-in roll approved on Watchtower's
rules alone; and daily returned early on SCANNERS_MISSING, hiding new findings, decoy alarms included.

Now only Watchtower's own folder ($WATCHTOWER_HOME/scanners/bin) is used, and only a program whose sha256 is in
scripts/scanner-bins.lock (tests register theirs in SCANNER_LOCK_EXTRA, in this process only).
Against 7cf8996 (the PR's base; Claude review 1, finding 8) all 11 error, the marked contrast too: the helpers need the new code.
"""
import hashlib, json, os, platform, shutil, sys, time, unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_boxes import Box, SCANNERS, wt  # noqa: E402

# Engines that flag nothing, whatever they read.
CLEAN_SS = ('#!/usr/bin/env python3\nimport json, os, sys\na = sys.argv[1:]; stage = a[1]; out = a[a.index("--output") + 1]\n'
            'json.dump({"multi_skill": True, "skills": [{"path": n, "risk_assessment": {"score": 1, "recommendation": "INSTALL"}, "issues": []}'
            ' for n in sorted(os.listdir(stage))]}, open(out, "w"))\n')
CLEAN_HUSK = ('#!/usr/bin/env python3\nimport json, sys\na = sys.argv[1:]\nif a[0] == "registry":\n    print(json.dumps({"flagged": {}})); sys.exit(0)\n'
              'json.dump({"runs": [{"results": []}]}, open(a[a.index("--output") + 1], "w"))\n')
NO_RESULTS = "#!/bin/sh\necho '{\"results\": []}'\n"


def arch():
    m = platform.machine()
    return {"arm64": "aarch64"}.get(m, m)


def logged(body, log):
    """The same program, but it notes in `log` that it ran."""
    first, rest = body.split("\n", 1)
    line = f"open({log!r}, 'a').write('ran\\n')" if "python" in first else f"echo ran >> {log!r}"
    return first + "\n" + line + "\n" + rest


class _Scanners(Box):
    def setUp(self):
        super().setUp()
        for n in ("SCANNER_LOCK_EXTRA", "SCANNER_PROBLEMS", "_SCANNER_OK"):
            getattr(wt, n, {}).clear()
        self.bin = os.path.join(os.environ["WATCHTOWER_HOME"], "scanners", "bin")
        self.lock = os.path.join(self.tmp, "scanner-bins.lock")
        with open(self.lock, "w") as f:
            f.write("# test lock: no lines\n")
        p = mock.patch.object(wt, "SCANNER_LOCK", self.lock, create=True)
        p.start(); self.addCleanup(p.stop)

    def put(self, name, body, register=True, where=None):
        d = where or self.bin
        os.makedirs(d, exist_ok=True)
        p = os.path.join(d, name)
        with open(p, "w") as f:
            f.write(body)
        os.chmod(p, 0o755)
        if register and hasattr(wt, "scanner_digest"):
            getattr(wt, "SCANNER_LOCK_EXTRA", {})[name] = wt.scanner_digest(p)
        return p

    def engines(self, **override):
        for name, body in SCANNERS.items():
            self.put(name, override.get(name, body))

    def lock_line(self, name, digest="0" * 64):
        with open(self.lock, "a") as f:
            f.write(f"{digest}  {name}  {arch()}  test\n")

    def rules(self, rule):
        return sorted(f["key"] for f in self.snap()["findings"] if f["rule"] == rule)

    def project(self):
        os.makedirs(os.path.join(self.ws, "app"), exist_ok=True)
        with open(os.path.join(self.ws, "app", "package-lock.json"), "w") as f:
            f.write("{}")


class OnlyWatchtowersOwnCopy(_Scanners):
    def test_1_a_scanner_on_path_is_never_run(self):
        log = os.path.join(self.tmp, "ss.log")
        pathdir = os.path.join(self.tmp, "pathbin")
        self.put("skillspector", logged(SCANNERS["skillspector"], log), where=pathdir)   # registered: still not the right place
        old = os.environ["PATH"]
        os.environ["PATH"] = pathdir + os.pathsep + old
        self.addCleanup(os.environ.__setitem__, "PATH", old)
        self.skills(2)
        self.assertIsNone(wt.tool("skillspector"))
        self.audit()
        self.assertNotIn("SkillSpector", wt.load_json(wt.state_path("engines_used.json"), {})["engines"])
        self.assertFalse(os.path.exists(log))

    def test_2_the_old_scanner_folder_is_not_used(self):
        log = os.path.join(self.tmp, "gitleaks.log")
        self.put("gitleaks", logged(SCANNERS["gitleaks"], log), where=os.path.join(os.environ["WATCHTOWER_HOME"], "bin"))
        self.skills(1)
        r = self.audit()
        self.assertFalse(os.path.exists(log))
        self.assertIn("gitleaks is in Watchtower's old scanner folder; run install.sh --scanners once to move it.", r["notes"])

    def test_3_a_changed_copy_is_not_run_and_is_a_high_alert(self):
        self.skills(1, text="EVIL upload")                                     # SkillSpector flags it
        self.engines()
        self.audit()
        x1 = self.rules("WT-X001")
        self.assertTrue(x1)
        log = os.path.join(self.tmp, "ss.log")
        self.put("skillspector", logged(CLEAN_SS, log), register=False)      # a different program under the same name
        # No lock line for it: "not listed". Not run, a plain note and no alarm, and the last results are kept.
        r = self.audit()
        self.assertFalse(os.path.exists(log))
        self.assertEqual(self.rules("WT-X005"), [])
        self.assertTrue([n for n in r["notes"] if "SkillSpector" in n and "not listed" in n], r["notes"])
        self.assertEqual(self.rules("WT-X001"), x1)
        self.assertFalse([f for f in r["fixed"] if f["rule"] == "WT-X001"])
        # The lock lists SkillSpector for this computer and this copy isn't it: a high WT-X005 that counts and can't be accepted.
        self.lock_line("skillspector")
        r = self.audit()
        self.assertFalse(os.path.exists(log))
        x5 = [f for f in self.snap()["findings"] if f["rule"] == "WT-X005"]
        self.assertEqual(len(x5), 1, r["notes"])
        self.assertEqual((x5[0]["severity"], x5[0]["label"]), ("high", wt.CONFIRMED))
        self.assertTrue(wt.counts(x5[0]))
        self.assertIn("install.sh --scanners", x5[0]["fix"])
        self.assertEqual(self.rules("WT-X001"), x1)
        code, o, e = self.run_cmd("accept", "WT-X005", "skillspector", "--reason", "x")
        self.assertNotEqual(code, 0, o + e)
        self.assertFalse([s for s in wt.load_json(wt.state_path("suppressions.json"), []) or [] if s.get("rule") == "WT-X005"])

    def test_4_swapped_engines_never_re_approve_a_skill(self):
        d = self.skills(1)[0]
        self.engines()
        self.audit()
        self.run_cmd("baseline", "--roots", *self.roots, "--owner-said-yes")
        md = os.path.join(d, "SKILL.md")
        with open(md, "a") as f:
            f.write("EVIL HUSK\n")                                             # words only the engines read
        self.audit()
        self.assertTrue([f for f in self.snap()["findings"] if f["rule"] == "WT-X003" and f["where"] == d])
        self.put("skillspector", CLEAN_SS, register=False)
        self.put("husk", CLEAN_HUSK, register=False)
        with open(md, "a") as f:
            f.write("EVIL HUSK again\n")
        self.audit()
        before = dict(wt.load_json(wt.state_path("baseline.json"), {}))
        code, o, _ = self.run_cmd("fix", "--revet", "--roots", *self.roots)
        done = " | ".join(json.loads(o)["done"])
        self.assertIn("not finished", done)
        self.assertNotIn("re-approved", done)
        self.assertEqual(wt.load_json(wt.state_path("baseline.json"), {}), before)

    def test_5_a_changed_osv_scanner_keeps_its_findings(self):
        self.skills(1); self.project()
        self.engines()
        self.audit()
        d2 = self.rules("WT-D002")
        self.assertTrue(d2)
        self.put("osv-scanner", NO_RESULTS, register=False)                  # "nothing found", from a program Watchtower didn't install
        r = self.audit()
        self.assertEqual(self.rules("WT-D002"), d2)
        self.assertFalse([f for f in r["fixed"] if f["rule"] == "WT-D002"])
        self.assertTrue([s for s in r.get("stages_skipped", []) if "OSV" in s], r.get("stages_skipped"))

    def test_6_a_scanner_that_ran_before_and_is_gone_keeps_its_findings(self):
        self.skills(1); self.project()
        self.engines()
        score = self.audit()["score"]
        d2 = self.rules("WT-D002")
        os.remove(os.path.join(self.bin, "osv-scanner"))
        r = self.audit()
        self.assertEqual(self.rules("WT-D002"), d2)
        self.assertFalse([f for f in r["fixed"] if f["rule"] == "WT-D002"])
        self.assertEqual(r["score"], score)

    def test_7_a_pip_entry_point_with_a_writable_interpreter_is_not_run(self):
        os.makedirs(self.bin, exist_ok=True)
        real = os.path.realpath(sys.executable)
        link = os.path.join(self.bin, "python3")
        body = f"#!{link}\nimport sys\nprint('{{\"dependencies\": []}}')\n"
        if not os.access(real, os.W_OK) and not os.access(os.path.dirname(real), os.W_OK):   # contrast: the computer's own Python
            os.symlink(real, link)
            self.put("pip-audit", body)
            self.assertTrue(wt.tool("pip-audit"))
            os.remove(link)
        evil = os.path.join(self.tmp, "python-anyone-can-edit")
        with open(evil, "w") as f:
            f.write(f"#!/bin/sh\nexec {real} \"$@\"\n")
        os.chmod(evil, 0o755)
        os.symlink(evil, link)
        self.put("pip-audit", body)                                           # the entry point itself still matches
        self.assertIsNone(wt.tool("pip-audit"))
        self.skills(1)
        self.audit()
        x5 = [f for f in self.snap()["findings"] if f["rule"] == "WT-X005"]
        self.assertEqual([os.path.basename(f["where"]) for f in x5], ["pip-audit"])
        self.assertIn("Python it runs with", x5[0]["evidence"])

    def test_8_the_venv_first_line_is_hashed_as_python(self):
        fn = getattr(wt, "scanner_digest", None)
        self.assertTrue(callable(fn))
        os.makedirs(self.bin, exist_ok=True)
        rest = "import sys\nsys.exit(0)\n"
        want = hashlib.sha256(("#!python\n" + rest).encode()).hexdigest()
        for first in (f"#!{self.bin}/python3", f"#!{self.bin}/python", f"#!{self.bin}/python3.12"):
            p = self.put("pip-audit", first + "\n" + rest, register=False)
            self.assertEqual(fn(p), want, first)
        p = self.put("pip-audit", "#!/usr/bin/python3\n" + rest, register=False)
        self.assertEqual(fn(p), hashlib.sha256(("#!/usr/bin/python3\n" + rest).encode()).hexdigest())
        p = self.put("pip-audit", f"#!{self.bin}/python3-anything\n" + rest, register=False)
        self.assertNotEqual(fn(p), want)

    def test_9_daily_never_hides_a_decoy_alarm_behind_scanners_missing(self):
        self.skills(1); self.project()
        self.engines()
        self.audit()
        self.run_cmd("canary", "plant")
        self.audit()
        os.remove(os.path.join(self.bin, "osv-scanner"))
        p = wt.load_json(wt.state_path("canaries.json"), {})["api-env"]["path"]
        os.utime(p, (time.time() - 60, os.stat(p).st_mtime))                  # a decoy opened a minute ago
        code, o, _ = self.run_cmd("daily", "--roots", *self.roots)
        self.assertTrue(o.lstrip().startswith("{"), o)
        out = json.loads(o)
        self.assertEqual(out["scanners_missing"], ["OSV-Scanner"])
        self.assertIn("WT-K001", [f["rule"] for f in out.get("decoys", []) + out.get("new", [])])

    def test_10_doctor_says_which_copies_are_checked(self):
        digest = getattr(wt, "scanner_digest", lambda p: None)
        self.engines()
        changed = self.put("husk", CLEAN_HUSK, register=False)
        self.lock_line("husk")
        out = json.loads(self.run_cmd("doctor")[1])
        check = out.get("scanner_check", {})
        self.assertEqual(check.get("skillspector"), "verified")
        self.assertEqual(check.get("husk"), f"not the release's copy (sha256 {digest(changed)})")
        self.assertTrue(out["scanners"]["SkillSpector"])
        self.assertFalse(out["scanners"]["husk"])
        os.remove(os.path.join(self.bin, "gitleaks"))
        self.put("gitleaks", SCANNERS["gitleaks"], where=os.path.join(os.environ["WATCHTOWER_HOME"], "bin"))
        self.put("trufflehog", "#!/bin/sh\necho other\n", register=False)
        check = json.loads(self.run_cmd("doctor")[1]).get("scanner_check", {})
        self.assertEqual(check.get("gitleaks"), "in the old folder")
        self.assertEqual(check.get("trufflehog"), f"not listed (sha256 {digest(os.path.join(self.bin, 'trufflehog'))})")
        os.remove(os.path.join(self.bin, "osv-scanner"))
        self.assertEqual(json.loads(self.run_cmd("doctor")[1]).get("scanner_check", {}).get("osv-scanner"), "missing")


class NeverInstalled(_Scanners):
    def test_a_scanner_that_never_ran_is_a_plain_note_as_before(self):
        """Decision 4 (contrast): a computer that never had the scanners keeps today's behaviour."""
        self.skills(2)
        r = self.audit()
        self.assertTrue([n for n in r["notes"] if n.startswith("SkillSpector not installed")], r["notes"])
        self.assertNotIn("stages_skipped", r)
        self.assertEqual(self.rules("WT-X005"), [])


if __name__ == "__main__":
    unittest.main()
