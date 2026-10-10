"""Ken's refinements of Oct 10 to "false alarms are never scary" (after Cloudflare's MIT-licensed security-audit skill)."""
import io, json, os, shutil, sys, tempfile, unittest, warnings
from contextlib import redirect_stdout, redirect_stderr

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "watchtower"))
import wt  # noqa: E402

warnings.simplefilter("ignore", ResourceWarning)
F = lambda rule, sev, where, source="watchtower", title="t", ev="ev": wt.finding(rule, title, sev, ["X"], where, ev, "fix", source=source)
ALL_AREAS = {w for w, _ in wt.ASK_AREAS}


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.env = {k: os.environ.get(k) for k in ("WATCHTOWER_HOME", "WT_DECOY_ROOT")}
        os.environ["WATCHTOWER_HOME"] = os.path.join(self.tmp, "wt")
        os.environ["WT_DECOY_ROOT"] = os.path.join(self.tmp, "decoys")

    def tearDown(self):
        for k, v in self.env.items():
            os.environ.pop(k, None) if v is None else os.environ.__setitem__(k, v)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def run_wt(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = wt.main(list(argv))
        return code, out.getvalue(), err.getvalue()


class NoSeverity(Base):
    def test_worth_a_look_has_no_severity_and_no_score_while_evidence_is_unchanged(self):
        ev = [F("WT-K001", "critical", "/tmp/.x/y"), F("WT-I001", "high", "/ws/s"), F("WT-A003", "medium", "rules")]
        pat = [F("WT-T005", "critical", "/ws/a/SKILL.md:3"), F("WT-T013", "high", "rollcall:B:routine:r:1")]
        out = wt.label_findings(ev + pat)
        self.assertEqual([f["severity"] for f in out[:3]], ["critical", "high", "medium"])
        self.assertEqual([f["severity"] for f in out[3:]], ["info", "info"])
        self.assertEqual(wt.score(out), wt.score(ev))
        self.assertEqual(wt.verdict(out[3:]), "Install")

    def test_corroborated_stays_confirmed_and_loud(self):
        out = wt.label_findings([F("WT-S002", "high", "/ws/k.env:4", source="gitleaks"), F("WT-S001", "high", "/ws/k.env:4")])
        self.assertEqual([(f["severity"], f["label"]) for f in out], [("high", wt.CONFIRMED)] * 2)

    def test_report_lists_worth_a_look_and_tips_apart(self):
        fs = wt.label_findings([F("WT-T013", "high", "rollcall:B:routine:r:1"), F("WT-R002", "medium", "rollcall:B:routine:r")])
        md = wt.render_md({"findings": fs, "score": 100, "grade": "A"}, [], "t")
        self.assertIn(f"## {wt.MAYBE_FINE}", md); self.assertIn("## Tips", md)
        self.assertIn("Worth a look", wt.extra_sections(fs)); self.assertIn("Tips", wt.extra_sections(fs))


class Tips(Base):
    def test_best_practice_checks_are_tips(self):
        self.assertEqual(wt.TIP_RULES, {"WT-R002", "WT-R003"})
        out = wt.label_findings([F("WT-R002", "medium", "export:routine-a.md"), F("WT-R003", "low", "export:routine-a.md")])
        self.assertEqual([(f["class"], f["label"], f["severity"]) for f in out], [("tip", wt.TIP, "info")] * 2)
        self.assertEqual(wt.score(out), (100, "A"))
        self.assertFalse(wt.TIP_RULES & wt.EVIDENCE_RULES)                     # no evidence rule became a tip


class AskFirstCovers(Base):
    def test_a_missing_approval_line_is_a_tip_when_ask_first_covers_the_action(self):
        f = F("WT-T013", "high", "export:routine-x.md:1", ev="send")
        self.assertEqual(wt.label_findings([f], ALL_AREAS)[0]["class"], "tip")
        self.assertEqual(wt.label_findings([f])[0]["class"], "pattern")         # nothing assumed without the rules
        gaps = F("WT-A003", "medium", "Auto-review rules", ev="sending email or messages")
        self.assertEqual(wt.ask_first_covered([gaps]), ALL_AREAS - {"sending email or messages"})
        out = wt.label_findings([f, gaps], wt.ask_first_covered([f, gaps]))
        self.assertEqual(out[0]["class"], "pattern")                             # sending isn't covered: still worth a look
        post = F("WT-T013", "high", "export:routine-y.md:1", ev="publish")
        self.assertEqual(wt.label_findings([post, gaps], wt.ask_first_covered([gaps]))[0]["class"], "tip")
        self.assertEqual(wt.ask_first_covered([F("WT-A003", "medium", "x", ev=", ".join(sorted(ALL_AREAS)))]), set())


class ScoreShowsCounts(Base):
    def test_the_score_always_carries_the_worth_a_look_and_tip_counts(self):
        fs = wt.label_findings([F("WT-T013", "high", "rollcall:B:routine:r:1"), F("WT-T005", "critical", "/ws/a/SKILL.md:3"),
                                F("WT-R002", "medium", "export:routine-a.md")])
        snap = {"score": 100, "grade": "A", "findings": fs, "at": "2026-10-10T07:00:00", "previous_score": None, "version": wt.VERSION}
        self.assertEqual(wt.score(fs)[0], 100)
        self.assertEqual(wt.score_line(snap), "100 · 2 worth a look · 1 tip")
        self.assertIn("Score 100 · 2 worth a look · 1 tip", wt.render_md(snap, [], "t"))
        self.assertIn("100 · 2 worth a look · 1 tip", wt.render_html(snap, [], "t"))
        os.makedirs(os.path.join(os.environ["WATCHTOWER_HOME"], "state"), exist_ok=True)
        wt.save_json(wt.state_path("last_findings.json"), snap)
        code, out, _ = self.run_wt("show", "WT-T013")
        self.assertIn("score 100 · 2 worth a look · 1 tip", out)
        src = open(wt.__file__).read()
        for where in ('"score_line": score_line(snap), "grade"', '{"score": snap["score"], "score_line": score_line(snap)}',
                      '"brief": path, "threat_level": threat_level(b, snap, top)[1], "score_line"', "{e(score_line(snap))}",
                      '"score": snap.get("score"), "score_line": score_line(snap)'):
            self.assertIn(where, src)   # audit, daily, brief (chat and page), doctor
