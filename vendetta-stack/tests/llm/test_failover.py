"""Validates the 3-tier deterministic failover cascade (nemotron → gemma → Cecur Heuristics).

`tests/smoke-test.sh` flips the mock Ollama state between classes (control endpoint) and runs one class per stage:
  Tier1PrimaryAnswers       — all models up
  Tier2ForensicTakesOver    — nemotron-3-nano:30b down
  Tier3HeuristicsNeverStall — every model down
"""
from __future__ import annotations

import unittest

import _live as live


class Tier1PrimaryAnswers(unittest.TestCase):
    def test_primary_model_answers_without_fallback(self) -> None:
        r = live.triage()
        self.assertEqual(r["meta"]["model"], live.PRIMARY_MODEL, r["meta"])
        self.assertFalse(r["meta"]["fallback"], r["meta"])
        self.assertEqual(r["meta"]["role"], "triage")
        live.assert_analysis(r["analysis"])


class Tier2ForensicTakesOver(unittest.TestCase):
    def test_forensic_model_takes_over_and_reason_is_recorded(self) -> None:
        r = live.triage()
        self.assertEqual(r["meta"]["model"], live.FORENSIC_MODEL, r["meta"])
        self.assertTrue(r["meta"]["fallback_reason"], "fallback reason not recorded")
        live.assert_analysis(r["analysis"])


class Tier3HeuristicsNeverStall(unittest.TestCase):
    def test_heuristics_answer_deterministically(self) -> None:
        first, second = live.triage(id="det-1"), live.triage(id="det-1")
        for r in (first, second):
            self.assertEqual(r["analysis"]["engineUsed"], "Cecur Heuristics")
            self.assertIs(r["meta"]["fallback"], True)
            self.assertEqual(r["meta"]["role"], "heuristic")
            self.assertEqual(r["meta"]["gpu_seconds"], 0, "heuristics must not meter GPU time")
            live.assert_analysis(r["analysis"])
        keys = ("severityAssessment", "mitreTactic", "mitreTechnique", "confidenceScore")
        self.assertEqual({k: first["analysis"][k] for k in keys}, {k: second["analysis"][k] for k in keys})


if __name__ == "__main__":
    unittest.main()
