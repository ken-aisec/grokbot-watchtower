"""v0.6.8: the first setup message warns that some findings will turn out to be fine, and says how to stop them."""
import os, unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class SetupLine(unittest.TestCase):
    def test_the_first_setup_message_says_some_alarms_will_be_fine(self):
        text = open(os.path.join(ROOT, "bot", "getting-started.md"), encoding="utf-8").read()
        self.assertIn("I’ll point out some things that turn out to be fine. That’s on purpose. Say ‘that’s fine’ and I’ll set it aside for 90 days.", text)
        audit = open(os.path.join(ROOT, "skills", "watchtower-audit", "SKILL.md"), encoding="utf-8").read()
        self.assertIn("that’s fine", audit); self.assertIn("wt.py accept", audit)



if __name__ == "__main__":
    unittest.main()
