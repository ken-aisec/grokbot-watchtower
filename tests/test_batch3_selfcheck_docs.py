"""Hardening batch 3, roadmap row 12 (Oct 16 review R12 and "Docs drift").

R12: `--version` was argparse's own version action, which answers while the arguments are read, before the self-check. A changed
copy still printed 0.7.1, so the setup skill took it as a good install and skipped the reinstall. The README and EGRESS had
drifted from the code: a test count, two sentences that no longer describe the score, a CLI list missing commands and flags,
and hosts the fix, vet and codescan contact.
Against 7cf8996 (the PR's base; Claude review 1, finding 8): 6 fail and the 2 marked contrasts pass.
"""
import os, re, subprocess, sys, unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import test_v068_hardening as v068  # noqa: E402
from test_v068_hardening import ROOT, wt  # noqa: E402


def text(*rel):
    with open(os.path.join(ROOT, *rel)) as f:
        return f.read()


def readme():
    return text("README.md")


def cli_block():
    return readme().split("## CLI", 1)[1].split("```", 2)[1]


class VersionAfterTheSelfCheck(v068.Base):
    install = v068.SelfCheck.install

    def version(self, app):
        p = subprocess.run([sys.executable, os.path.join(app, "watchtower", "wt.py"), "--version"], capture_output=True, text=True,
                           env=dict(os.environ), timeout=120)
        return p.returncode, p.stdout, p.stderr

    def test_a_changed_copy_never_prints_its_version(self):
        app = self.install()
        with open(os.path.join(app, "watchtower", "wt.py"), "a") as f:
            f.write("\n# changed\n")
        code, out, err = self.version(app)
        self.assertEqual(code, 4, out + err)
        self.assertIn("SELF-CHECK FAILED", out)
        self.assertIn("1 problem (listed in Watchtower's ledger)", out)            # Claude review 1 (9): a count, never names
        self.assertNotIn("watchtower/wt.py", out)
        self.assertNotIn(wt.VERSION, out)

    def test_a_clean_install_prints_its_version(self):
        """Contrast (Claude review 1, finding 8): passes on 7cf8996 too, where --version printed it without any check."""
        app = self.install()
        code, out, err = self.version(app)
        self.assertEqual((code, out.strip()), (0, wt.VERSION), err)

    def test_a_developer_checkout_prints_its_version(self):
        """Contrast (Codex, batch 3 round 1): passes on 7cf8996 too; it guards that the new self-check doesn't break checkouts."""
        p = subprocess.run([sys.executable, os.path.join(ROOT, "watchtower", "wt.py"), "--version"], capture_output=True, text=True,
                           env=dict(os.environ), timeout=120)
        self.assertEqual((p.returncode, p.stdout.strip()), (0, wt.VERSION), p.stderr)


class Readme(unittest.TestCase):
    def test_the_test_count_is_current(self):
        count = unittest.TestLoader().discover(os.path.join(ROOT, "tests"), top_level_dir=os.path.join(ROOT, "tests")).countTestCases()
        m = re.search(r"runs more than (\d+) tests", readme())
        self.assertTrue(m, "README says 'runs more than N tests'")
        n = int(m.group(1))
        self.assertTrue(0.9 * count <= n <= count, (n, count))

    def test_every_command_and_flag_is_in_the_cli_list(self):
        build = getattr(wt, "build_parser", None)
        self.assertTrue(callable(build), "wt.build_parser()")
        block, ap = cli_block(), build()
        missing = []
        def flags(p):
            return [o for a in p._actions for o in a.option_strings if o.startswith("--") and o != "--help"]
        for o in flags(ap):
            if o not in block:
                missing.append(o)
        subs = next(a for a in ap._actions if isinstance(a, wt.argparse._SubParsersAction))
        for name, p in subs.choices.items():
            if not re.search(r"(?<![\w-])" + re.escape(name) + r"(?![\w-])", block):
                missing.append(name)
            missing += [f"{name} {o}" for o in flags(p) if o not in block]
        self.assertEqual(missing, [])

    def test_the_stale_sentences_are_gone(self):
        t = readme()
        self.assertNotIn("corroborated critical", t)
        self.assertNotIn("count only when two scanners agree", t)
        self.assertIsNone(re.search(r"runs \d+ tests", t))


class Egress(unittest.TestCase):
    def test_every_host_the_code_contacts_is_listed(self):
        t = text("EGRESS.md")
        for word in ("semgrep", "--upgrade-projects", "registry.npmjs.org", "crates.io", "git clone"):
            self.assertIn(word, t)


class CodescanNote(unittest.TestCase):
    def test_no_advice_to_install_an_unchecked_semgrep(self):
        src = text("watchtower", "wt.py")
        self.assertNotIn("install semgrep for deeper analysis", src)
        self.assertIn("semgrep isn't one of Watchtower's checked scanners", src)


if __name__ == "__main__":
    unittest.main()
