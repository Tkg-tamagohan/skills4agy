#!/usr/bin/env python3
"""spec-cold-review 仕様準備度プリセットの単体テスト（テスト ID: SC-01–SC-05）。

presets/spec_readiness_check.json のスキーマ整合性、否定疑問回避とキー規約、
run_decisions.validate_payload() との結合、--dry-run 実行、およびモック応答による
テーブル整形を Python 標準ライブラリのみで決定論的に検証する。
"""

from __future__ import annotations

import contextlib
import io
import json
from pathlib import Path
import re
import sys
import unittest

SKILL_DIR = Path(__file__).resolve().parents[1]
PRESET_PATH = SKILL_DIR / "presets" / "spec_readiness_check.json"
DECISIONS_SCRIPTS_DIR = Path(__file__).resolve().parents[2] / "gemini-decisions-api" / "scripts"
if str(DECISIONS_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(DECISIONS_SCRIPTS_DIR))

import run_decisions  # noqa: E402

QUESTION_KEY_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
ENGLISH_NEGATIVE_PATTERN = re.compile(
    r"\b(?:not|isn't|aren't|doesn't|don't|wasn't|weren't|won't|can't|couldn't|"
    r"shouldn't|wouldn't|hasn't|haven't|hadn't|no|never|without|none|nothing|neither|nor)\b",
    re.IGNORECASE,
)
JAPANESE_NEGATIVE_PATTERNS = ("ないか", "ではないか", "ませんか")

EXPECTED_NOUL_KEYS = (
    "states_clear_objectives",
    "identifies_current_limits",
    "explains_new_approach",
    "specifies_risks_and_tradeoffs",
    "estimates_cost_and_timeline",
    "defines_success_metrics",
    "has_undefined_project_terms",
    "has_ambiguous_boundary_rules",
    "leaves_design_decisions_to_implementer",
    "specifies_concrete_verification_plan",
)
EXPECTED_SCORE_KEY = "spec_readiness_score"
EXPECTED_SCORE_CRITERIA = [
    "0: missing core objectives, context, and actionable design details",
    "1: states high-level goals while leaving major constraints, boundaries, and verification unspecified",
    "2: covers basic approach and scope while leaving key tradeoffs, edge cases, or design choices unresolved",
    "3: clearly specifies objectives, approach, boundaries, and risks with only minor clarifications remaining",
    "4: complete, unambiguous, self-contained specification with concrete verification criteria",
]


class _MockHTTPResponse:
    def __init__(self, body: dict):
        self._bytes = json.dumps(body, ensure_ascii=False).encode("utf-8")

    def read(self) -> bytes:
        return self._bytes

    def __enter__(self) -> _MockHTTPResponse:
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        return False


class TestSpecReadinessPreset(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        raw_bytes = PRESET_PATH.read_bytes()
        cls.raw_bytes = raw_bytes
        cls.preset = json.loads(raw_bytes.decode("utf-8"))

    def test_sc_01_preset_contains_required_eleven_questions(self) -> None:
        """SC-01: UTF-8 BOM なしで 11 問（noul 10 問 + score 1 問の 5 段階 criteria）を備える。"""
        self.assertFalse(self.raw_bytes.startswith(b"\xef\xbb\xbf"), "UTF-8 BOM は禁止")
        self.assertIsInstance(self.preset, dict)
        expected_keys = set(EXPECTED_NOUL_KEYS) | {EXPECTED_SCORE_KEY}
        self.assertEqual(len(self.preset), 11)
        self.assertEqual(set(self.preset.keys()), expected_keys)

        for key in EXPECTED_NOUL_KEYS:
            with self.subTest(key=key):
                self.assertEqual(self.preset[key]["type"], "noul")

        score_q = self.preset[EXPECTED_SCORE_KEY]
        self.assertEqual(score_q["type"], "score")
        self.assertEqual(len(score_q["criteria"]), 5)
        self.assertEqual(score_q["criteria"], EXPECTED_SCORE_CRITERIA)

    def test_sc_02_keys_affirmative_instructions_and_score_levels(self) -> None:
        """SC-02: 全質問キーが規約に適合し、instructions に日英の否定表現を含まない。"""
        for q_key, q_body in self.preset.items():
            with self.subTest(q_key=q_key):
                self.assertRegex(q_key, QUESTION_KEY_PATTERN)
                instructions = q_body.get("instructions")
                self.assertIsInstance(instructions, str)
                self.assertTrue(instructions.strip())
                self.assertIsNone(
                    ENGLISH_NEGATIVE_PATTERN.search(instructions),
                    f"英語の否定語を含めないこと: {instructions}",
                )
                for neg_ja in JAPANESE_NEGATIVE_PATTERNS:
                    self.assertNotIn(neg_ja, instructions)

                if q_body["type"] == "score":
                    criteria = q_body.get("criteria")
                    self.assertIsInstance(criteria, list)
                    self.assertGreaterEqual(len(criteria), 2)
                    self.assertLessEqual(len(criteria), 10)
                    for idx, level in enumerate(criteria):
                        self.assertIsInstance(level, str)
                        self.assertTrue(level.startswith(f"{idx}: "))

    def test_sc_03_validate_payload_with_spec_text_passes(self) -> None:
        """SC-03: 仕様書テキストと組み合わせて run_decisions.validate_payload() がエラー 0 件で通る。"""
        payload = {
            "model": run_decisions.DEFAULT_MODEL,
            "input": [
                {
                    "type": "text",
                    "text": (
                        "Goal: Introduce an idempotent retry queue for webhook delivery.\n"
                        "Limits: Current worker drops events after one timeout.\n"
                        "Verification: Run integration tests for duplicate delivery."
                    ),
                }
            ],
            "questions": self.preset,
        }
        errors = run_decisions.validate_payload(payload)
        self.assertEqual(errors, [])

    def test_sc_04_dry_run_cli_with_preset_succeeds(self) -> None:
        """SC-04: run_decisions.py の --questions と --dry-run の結合が API キーなしで成功する。"""
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = run_decisions.main(
                [
                    "--text",
                    "Sample spec text describing objectives, limits, and verification.",
                    "--questions",
                    str(PRESET_PATH),
                    "--min-confidence",
                    "0.70",
                    "--format",
                    "table",
                    "--dry-run",
                ],
                env={},
            )
        self.assertEqual(code, 0)
        self.assertEqual(stderr.getvalue(), "")
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["model"], run_decisions.DEFAULT_MODEL)
        self.assertEqual(len(payload["input"]), 1)
        self.assertEqual(payload["input"][0]["type"], "text")
        self.assertEqual(set(payload["questions"].keys()), set(self.preset.keys()))

    def test_sc_05_mock_api_response_formats_table_and_escalation(self) -> None:
        """SC-05: モック応答で enrich_response() と format_table() の全 11 問と ESCALATE 判定を検証する。"""
        mock_response = {
            "answers": {
                "states_clear_objectives": {"type": "noul", "noul": 0.94, "confidence": 0.94},
                "identifies_current_limits": {"type": "noul", "noul": 0.88, "confidence": 0.88},
                "explains_new_approach": {"type": "noul", "noul": 0.85, "confidence": 0.85},
                "specifies_risks_and_tradeoffs": {"type": "noul", "noul": 0.61, "confidence": 0.61},
                "estimates_cost_and_timeline": {"type": "noul", "noul": 0.15, "confidence": 0.85},
                "defines_success_metrics": {"type": "noul", "noul": 0.82, "confidence": 0.82},
                "has_undefined_project_terms": {"type": "noul", "noul": 0.78, "confidence": 0.78},
                "has_ambiguous_boundary_rules": {"type": "noul", "noul": 0.64, "confidence": 0.64},
                "leaves_design_decisions_to_implementer": {"type": "noul", "noul": 0.74, "confidence": 0.74},
                "specifies_concrete_verification_plan": {"type": "noul", "noul": 0.90, "confidence": 0.90},
                "spec_readiness_score": {
                    "type": "score",
                    "score": 2.40,
                    "legend": {str(i): item for i, item in enumerate(EXPECTED_SCORE_CRITERIA)},
                    "probabilities": {"0": 0.00, "1": 0.10, "2": 0.50, "3": 0.30, "4": 0.10},
                    "confidence": 0.50,
                },
            },
            "usage": {"total_input_tokens": 420, "total_output_tokens": 0},
        }

        enriched = run_decisions.enrich_response(mock_response, min_confidence=0.70)
        self.assertFalse(enriched["answers"]["states_clear_objectives"]["needs_escalation"])
        self.assertTrue(enriched["answers"]["specifies_risks_and_tradeoffs"]["needs_escalation"])
        self.assertTrue(enriched["answers"]["has_ambiguous_boundary_rules"]["needs_escalation"])
        self.assertEqual(enriched["answers"]["spec_readiness_score"]["normalized_score"], 0.6)
        self.assertEqual(enriched["answers"]["spec_readiness_score"]["top_level"], "2")

        direct_table = run_decisions.format_table(enriched)
        self.assertIn("norm=0.60", direct_table)

        def fake_opener(req, timeout=30.0):
            return _MockHTTPResponse(mock_response)

        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = run_decisions.main(
                [
                    "--text",
                    "Sample spec text for mock verification.",
                    "--questions",
                    str(PRESET_PATH),
                    "--min-confidence",
                    "0.70",
                    "--format",
                    "table",
                ],
                opener=fake_opener,
                env={"GEMINI_API_KEY": "dummy-test-key"},
            )
        self.assertEqual(code, 0)
        self.assertEqual(stderr.getvalue(), "")
        table = stdout.getvalue()
        rows = {
            line.split("|")[1].strip(): line
            for line in table.splitlines()
            if line.startswith("| ") and not line.startswith("| question ")
        }
        for q_key in self.preset:
            self.assertIn(q_key, rows)
        self.assertNotIn("ESCALATE", rows["states_clear_objectives"])
        self.assertIn("ESCALATE", rows["specifies_risks_and_tradeoffs"])
        self.assertIn("ESCALATE", rows["has_ambiguous_boundary_rules"])
        self.assertIn("ESCALATE", rows[EXPECTED_SCORE_KEY])
        self.assertIn("norm=0.60", rows[EXPECTED_SCORE_KEY])
        self.assertIn("output_tokens=0", table)


if __name__ == "__main__":
    unittest.main()
