"""The benchmark is also a test: every planted leak caught, no harmless lookalike flagged."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "bench"))

import run as bench  # noqa: E402


class BenchTests(unittest.TestCase):
    def test_all_planted_caught_and_no_false_alarms(self):
        r = bench.run()
        self.assertEqual(r["missed"], [])
        self.assertEqual(r["false_alarms"], [])
        self.assertGreaterEqual(r["planted"], 30)
        self.assertGreaterEqual(r["benign"], 30)

    def test_fake_values_are_never_printed_in_findings(self):
        from leash.secrets import redact
        f = bench.fakes()
        for _, tmpl in bench.PLANTED:
            out = redact(bench.rule(tmpl.format(**f)))
            for v in f.values():
                self.assertNotIn(v, out, tmpl)


if __name__ == "__main__":
    unittest.main()
