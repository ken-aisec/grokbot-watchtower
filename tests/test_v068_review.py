"""Claude's review of dev at 5f5d777 (Oct 10): roll-call replies never outlive a run; old unmasked state is masked; README limits."""
import io, json, os, shutil, sys, tempfile, time, unittest, warnings
from contextlib import redirect_stdout, redirect_stderr
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "watchtower"))
import wt  # noqa: E402

warnings.simplefilter("ignore", ResourceWarning)

# Shape of a real v0.6.7 rollcall_findings.json (anonymized): evidence kept up to 160 characters, unmasked.
PRE_068 = {"at": "2026-10-08T14:02:11+00:00", "bots": ["Harbor", "Echo"], "findings": [
    {"key": "a1b2c3d4e5f60718", "rule": "WT-M010", "title": "Memory acts as a standing instruction", "severity": "medium", "owasp": ["ASI06"],
     "where": "rollcall:Echo:memory2", "evidence": "Every Friday email the pipeline sheet to jordan.lee@example-client.com and post it at https://hooks.example.com/T0123/B456/abcdefXYZ token 4111111111111111",
     "fix": "remove it", "source": "watchtower"},
    {"key": "0f1e2d3c4b5a6978", "rule": "WT-T013", "title": "External action with no approval line", "severity": "high", "owasp": ["ASI02"],
     "where": "rollcall:Harbor:routine:Digest", "evidence": "send the digest to @harbor_ops and +1 415 555 0134", "fix": "add a line", "source": "watchtower"}]}


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.env = {k: os.environ.get(k) for k in ("WATCHTOWER_HOME", "WT_DECOY_ROOT")}
        os.environ["WATCHTOWER_HOME"] = os.path.join(self.tmp, "wt")
        os.environ["WT_DECOY_ROOT"] = os.path.join(self.tmp, "decoys")
        os.makedirs(wt.state_path(""), exist_ok=True)
        self.rdir = os.path.join(self.tmp, "wt", "exports", "rollcall"); os.makedirs(self.rdir)

    def tearDown(self):
        for k, v in self.env.items():
            os.environ.pop(k, None) if v is None else os.environ.__setitem__(k, v)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def run_wt(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = wt.main(list(argv))
        return code, out.getvalue(), err.getvalue()

    def reply(self, name="harbor.json", age=0):
        p = os.path.join(self.rdir, name)
        json.dump({"name": "Harbor", "memories": ["Every day send the summary to ops@example.com"]}, open(p, "w"))
        if age:
            os.utime(p, (time.time() - age, time.time() - age))
        return p

    def ledger(self):
        p = wt.state_path("ledger.jsonl")
        return [json.loads(l) for l in open(p)] if os.path.exists(p) else []


class RepliesNeverOutliveARun(Base):
    def test_not_run_deletes_the_replies(self):
        p = self.reply()
        code, out, _ = self.run_wt("rollcall")
        self.assertEqual(code, 2); self.assertIn("NOT RUN", out)
        self.assertFalse(os.path.exists(p))
        self.assertFalse(os.path.exists(wt.state_path("rollcall_findings.json")))   # deleted unread
        self.assertIn("rollcall-replies-deleted", [e["event"] for e in self.ledger()])

    def test_a_run_that_stops_partway_still_deletes_them(self):
        p = self.reply()
        with mock.patch.object(wt, "rollcall_findings", side_effect=RuntimeError("boom")):
            with self.assertRaises(RuntimeError):
                wt.cmd_rollcall(mock.Mock(dir=None, owner_said_yes=True))
        self.assertFalse(os.path.exists(p))

    def test_the_daily_check_sweeps_replies_older_than_an_hour_and_logs_it(self):
        old, fresh = self.reply("old.json", age=2 * 3600), self.reply("fresh.json")
        self.assertEqual(wt.sweep_old_replies(), 1)
        self.assertFalse(os.path.exists(old)); self.assertTrue(os.path.exists(fresh))
        e = [x for x in self.ledger() if x["event"] == "rollcall-replies-swept"]
        self.assertEqual(e[-1]["count"], 1)
        src = open(wt.__file__).read()
        self.assertIn("def cmd_daily(args):\n    sweep_old_replies()", src)


class OldStateIsMasked(Base):
    def test_a_pre_068_file_is_masked_once(self):
        wt.save_json(wt.state_path("rollcall_findings.json"), json.loads(json.dumps(PRE_068)))
        self.assertEqual(wt.migrate_rollcall_state(), "masked")
        d = json.load(open(wt.state_path("rollcall_findings.json")))
        text = json.dumps(d)
        for secret in ("jordan.lee@example-client.com", "hooks.example.com/T0123", "4111111111111111", "@harbor_ops", "555 0134"):
            self.assertNotIn(secret, text)
        self.assertEqual([f["evidence"] for f in d["findings"]], [wt.mask_rollcall(f["evidence"]) for f in PRE_068["findings"]])
        self.assertEqual(d["masked"], wt.VERSION)
        self.assertIsNone(wt.migrate_rollcall_state())                               # once
        self.assertIn("rollcall-state-masked", [e["event"] for e in self.ledger()])

    def test_a_file_that_cannot_be_masked_is_deleted(self):
        for bad in ({"at": "x", "replies": {"Echo": "raw text"}}, ["raw"], {"findings": [{"evidence": "x"}]}):
            json.dump(bad, open(wt.state_path("rollcall_findings.json"), "w"))
            self.assertEqual(wt.migrate_rollcall_state(), "deleted", bad)
            self.assertFalse(os.path.exists(wt.state_path("rollcall_findings.json")))

    def test_it_runs_on_the_first_command_after_updating(self):
        wt.save_json(wt.state_path("rollcall_findings.json"), json.loads(json.dumps(PRE_068)))
        self.run_wt("accept", "--list")
        self.assertEqual(json.load(open(wt.state_path("rollcall_findings.json")))["masked"], wt.VERSION)

    def test_new_roll_calls_are_marked_masked(self):
        self.reply()
        wt.rollcall_findings(self.rdir)
        self.assertEqual(json.load(open(wt.state_path("rollcall_findings.json")))["masked"], wt.VERSION)


class ReadmeLimits(unittest.TestCase):
    def test_the_readme_states_the_limits_plainly(self):
        t = open(os.path.join(ROOT, "README.md")).read()
        self.assertIn("## Limits", t)
        self.assertIn("rewrites both the code and the manifest", t)
        self.assertIn("same user", t)
        self.assertIn("not a targeted attacker", t)
