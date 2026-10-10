"""v0.6.8: a false alarm is never scary. Pattern findings are labelled "Worth a look", capped at medium unless backed up,
and weigh a fifth in the score; evidence findings stay exactly as loud as before."""
import os, sys, tempfile, unittest, warnings

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "watchtower"))
import wt  # noqa: E402

warnings.simplefilter("ignore", ResourceWarning)
F = lambda rule, sev, where, source="watchtower", title="t": wt.finding(rule, title, sev, ["X"], where, "ev", "fix", source=source)


class QuietFalseAlarms(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.skill = os.path.join(self.tmp, "s"); os.makedirs(self.skill)
        open(os.path.join(self.skill, "SKILL.md"), "w").write("---\nname: s\n---\n")
        self.md = os.path.join(self.skill, "SKILL.md")

    def test_every_evidence_finding_keeps_its_severity_and_label(self):
        ev = [F(r, sev, f"{self.md}:1") for r in sorted(wt.EVIDENCE_RULES) for sev in ("critical", "high", "medium", "low")]
        ev.append(F("WT-S001", "critical", self.md, title=wt.KEY_LIVE))                        # a key the provider says works
        ev.append(F("WT-H006", "medium", "/home/box/.bash_history", title=wt.HISTORY_SHRANK))      # the file got smaller
        out = wt.label_findings(ev)
        self.assertEqual([f["severity"] for f in out], [f["severity"] for f in ev])
        self.assertTrue(all(f["label"] == wt.CONFIRMED and "severity_was" not in f for f in out))

    def test_evidence_only_scores_are_unchanged(self):
        for fs in ([F("WT-K001", "critical", "/tmp/.archive/payments.env")],
                   [F("WT-I001", "high", self.md), F("WT-D002", "high", "/ws/app"), F("WT-S004", "high", "browser"), F("WT-A003", "medium", "rules")],
                   [F("WT-X003", "critical", self.skill), F("WT-C003", "high", "settings")]):
            self.assertEqual(wt.score(wt.label_findings(fs)), wt.score(fs))   # unlabelled findings count in full, as before v0.6.8

    def test_a_lone_pattern_finding_is_capped_at_medium(self):
        out = wt.label_findings([F("WT-T013", "high", "rollcall:Bot:routine:x"), F("WT-T005", "critical", f"{self.md}:3"),
                                 F("WT-S002", "high", "/ws/notes.txt", source="gitleaks"), F("WT-X001", "high", "/ws/other", source="skillspector")])
        self.assertEqual([f["severity"] for f in out], ["medium"] * 4)
        self.assertEqual([f["severity_was"] for f in out], ["high", "critical", "high", "high"])
        self.assertTrue(all(f["label"] == wt.MAYBE_FINE for f in out))
        low = wt.label_findings([F("WT-T016", "low", f"{self.md}:2")])[0]
        self.assertEqual((low["severity"], low["label"]), ("low", wt.MAYBE_FINE))                  # never raised

    def test_corroboration_keeps_a_pattern_finding_loud(self):
        # a second engine on the same file
        out = wt.label_findings([F("WT-S002", "high", "/ws/k.env:4", source="gitleaks"), F("WT-S001", "high", "/ws/k.env:4")])
        self.assertEqual([(f["severity"], f["label"]) for f in out], [("high", wt.CONFIRMED)] * 2)
        # an evidence finding at the same skill folder
        out = wt.label_findings([F("WT-T005", "critical", f"{self.md}:3"), F("WT-I001", "high", self.skill)])
        self.assertEqual((out[0]["severity"], out[0]["class"]), ("critical", "corroborated"))
        # two different loud pattern rules in one skill
        out = wt.label_findings([F("WT-T002", "high", f"{self.md}:5"), F("WT-T001", "critical", f"{self.md}:5")])
        self.assertEqual([f["severity"] for f in out], ["high", "critical"])
        # the same rule twice, or a finding somewhere else, is not a second opinion
        out = wt.label_findings([F("WT-T005", "critical", f"{self.md}:3"), F("WT-T005", "critical", f"{self.md}:9"),
                                 F("WT-S002", "high", "/elsewhere/x", source="gitleaks")])
        self.assertEqual([f["severity"] for f in out], ["medium"] * 3)

    def test_roll_call_findings_only_back_up_their_own_bot_line(self):
        out = wt.label_findings([F("WT-T013", "high", "rollcall:Alpha:routine:Brief:1"), F("WT-L001", "high", "rollcall:Alpha"),
                                 F("WT-M010", "medium", "rollcall:Bravo:memory1"), F("WT-T013", "high", "rollcall:Bravo:routine:Digest:1")])
        self.assertEqual([f["class"] for f in out], ["pattern", "evidence", "pattern", "pattern"])
        self.assertEqual(out[0]["severity"], "medium")

    def test_pattern_findings_weigh_a_fifth(self):
        p = wt.label_findings([F("WT-T013", "medium", "rollcall:B:routine:r")])
        e = wt.label_findings([F("WT-A003", "medium", "rules")])
        self.assertEqual(p[0]["class"], "pattern")
        self.assertEqual(wt.score(e)[0], 100 - round(wt.SCORE_BASE["medium"]))
        self.assertEqual(wt.score(p)[0], 100 - round(wt.PATTERN_WEIGHT * wt.SCORE_BASE["medium"]))
        many = wt.label_findings([F(f"WT-T00{i}", "critical", f"/ws/s{i}/SKILL.md:1") for i in range(1, 9)])
        self.assertGreater(wt.score(many)[0], wt.score([F(f"WT-T00{i}", "critical", f"/ws/s{i}/SKILL.md:1") for i in range(1, 9)])[0])

    def test_labels_reach_the_report_and_chat(self):
        fs = wt.label_findings([F("WT-K001", "critical", "/tmp/.archive/payments.env"), F("WT-T013", "high", "rollcall:B:routine:r")])
        self.assertEqual([wt.compact(f)["label"] for f in fs], [wt.CONFIRMED, wt.MAYBE_FINE])
        self.assertEqual(wt.plain(fs[1])["label"], wt.MAYBE_FINE)
        md = wt.render_md({"findings": fs, "score": 90, "grade": "A"}, [], "t")
        self.assertIn(f"{wt.CONFIRMED}: ", md); self.assertIn(f"{wt.MAYBE_FINE}: ", md)


if __name__ == "__main__":
    unittest.main()
