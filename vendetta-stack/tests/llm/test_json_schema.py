"""Validates AIIncidentAnalysis conformance of live gateway answers (contract §4.2; strict JSON, temperature 0.2)."""
from __future__ import annotations

import unittest

import _live as live


class AIIncidentAnalysisConformance(unittest.TestCase):
    def test_triage_answer_is_schema_valid(self) -> None:
        live.assert_analysis(live.triage()["analysis"])

    def test_forensic_answer_is_schema_valid(self) -> None:
        r = live.triage(role="forensic")
        live.assert_analysis(r["analysis"])
        self.assertIn(r["meta"]["role"], {"forensic", "heuristic"})

    def test_metadata_is_complete_and_metered(self) -> None:
        meta = live.triage()["meta"]
        for key in ("model", "role", "fallback", "latency_ms", "gpu_seconds", "tokens_in", "tokens_out", "guardrail"):
            self.assertIn(key, meta, f"meta.{key} missing")
        self.assertGreaterEqual(meta["gpu_seconds"], 0)

    def test_json_array_input_returns_one_result_per_record(self) -> None:
        code, res = live.gateway("POST", "/triage", [live.alert(), live.alert()])
        self.assertEqual(code, 200, res)
        self.assertEqual(len(res["results"]), 2)
        for item in res["results"]:
            live.assert_analysis(item["analysis"])

    def test_validator_rejects_violations(self) -> None:
        good = live.triage()["analysis"]
        for bad in ({**good, "severityAssessment": "SEVERE"}, {**good, "confidenceScore": 101},
                    {**good, "unexpected": 1}, {k: v for k, v in good.items() if k != "mitreTactic"}):
            with self.assertRaises(AssertionError):
                live.assert_analysis(bad)


if __name__ == "__main__":
    unittest.main()
