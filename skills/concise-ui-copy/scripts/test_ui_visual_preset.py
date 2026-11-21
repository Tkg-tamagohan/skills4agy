#!/usr/bin/env python3
"""concise-ui-copy UI 視覚・冗長文言プリセットの単体テスト（テスト ID: P5-01–P5-05）。

presets/ui_visual_check.json のスキーマ整合性、否定疑問回避とキー規約、
run_decisions.validate_payload() との結合、--dry-run 実行、およびモック応答による
テーブル整形を Python 標準ライブラリのみで決定論的に検証する。
"""

from __future__ import annotations

import base64
import contextlib
import io
import json
from pathlib import Path
import re
import struct
import sys
import tempfile
import unittest
import zlib

SKILL_DIR = Path(__file__).resolve().parents[1]
PRESET_PATH = SKILL_DIR / "presets" / "ui_visual_check.json"
DECISIONS_SCRIPTS_DIR = Path(__file__).resolve().parents[2] / "gemini-decisions-api" / "scripts"
if str(DECISIONS_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(DECISIONS_SCRIPTS_DIR))

import run_decisions  # noqa: E402

QUESTION_KEY_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
ENGLISH_NEGATIVE_PATTERN = re.compile(
    r"\b(?:not|isn't|aren't|doesn't|don't|wasn't|weren't|won't|can't|couldn't|shouldn't|never)\b",
    re.IGNORECASE,
)
JAPANESE_NEGATIVE_PATTERNS = ("ないか", "ではないか", "ませんか")

EXPECTED_NOUL_KEYS = (
    "has_layout_breakage",
    "has_text_truncation",
    "has_redundant_lead_copy",
    "has_welcome_or_guide_banner",
    "has_redundant_secondary_label",
    "has_verbose_dialog_or_empty_state",
)
EXPECTED_VISUAL_CLARITY_CRITERIA = [
    "0: severe layout or legibility defects",
    "1: cluttered with excessive redundant copy",
    "2: usable but noticeable redundant labels or spacing issues",
    "3: clean layout with minor copy redundancy",
    "4: concise, well-aligned, and scannable UI",
]


def _make_minimal_png_bytes() -> bytes:
    """最小の 1x1 RGBA PNG バイト列を生成する。"""
    def chunk(tag: bytes, data: bytes) -> bytes:
        crc = zlib.crc32(tag + data) & 0xFFFFFFFF
        return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", crc)

    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 6, 0, 0, 0)
    idat = zlib.compress(b"\x00\x00\x00\x00\xff")
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"IDAT", idat) + chunk(b"IEND", b"")


class _MockHTTPResponse:
    def __init__(self, body: dict):
        self._bytes = json.dumps(body, ensure_ascii=False).encode("utf-8")

    def read(self) -> bytes:
        return self._bytes

    def __enter__(self) -> _MockHTTPResponse:
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        return False


class TestUiVisualPreset(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        raw_bytes = PRESET_PATH.read_bytes()
        cls.raw_bytes = raw_bytes
        cls.preset = json.loads(raw_bytes.decode("utf-8"))

    def test_p5_01_preset_contains_required_seven_questions(self) -> None:
        """P5-01: プリセット JSON が計画書どおりの 7 問と visual_clarity の 5 段階 criteria を備える。"""
        self.assertFalse(self.raw_bytes.startswith(b"\xef\xbb\xbf"), "UTF-8 BOM は禁止")
        self.assertIsInstance(self.preset, dict)
        expected_keys = set(EXPECTED_NOUL_KEYS) | {"visual_clarity"}
        self.assertEqual(set(self.preset.keys()), expected_keys)

        for key in EXPECTED_NOUL_KEYS:
            with self.subTest(key=key):
                self.assertEqual(self.preset[key]["type"], "noul")

        score_q = self.preset["visual_clarity"]
        self.assertEqual(score_q["type"], "score")
        self.assertEqual(score_q["criteria"], EXPECTED_VISUAL_CLARITY_CRITERIA)

    def test_p5_02_keys_affirmative_instructions_and_score_levels(self) -> None:
        """P5-02: 全質問キーが正規表現に適合し、instructions が否定疑問を避けた肯定文であり、score 段階数が 2〜10 段階に収まる。"""
        for q_key, q_body in self.preset.items():
            with self.subTest(q_key=q_key):
                self.assertRegex(q_key, QUESTION_KEY_PATTERN)
                instructions = q_body.get("instructions")
                self.assertIsInstance(instructions, str)
                self.assertTrue(instructions.strip())
                self.assertIsNone(
                    ENGLISH_NEGATIVE_PATTERN.search(instructions),
                    f"英語の否定表現を含めないこと: {instructions}",
                )
                for neg_ja in JAPANESE_NEGATIVE_PATTERNS:
                    self.assertNotIn(neg_ja, instructions)

                if q_body["type"] == "score":
                    criteria = q_body.get("criteria")
                    self.assertIsInstance(criteria, list)
                    self.assertGreaterEqual(len(criteria), 2)
                    self.assertLessEqual(len(criteria), 10)
                    for level in criteria:
                        self.assertIsInstance(level, str)
                        self.assertTrue(level.strip())

    def test_p5_03_validate_payload_with_text_and_dummy_png_passes(self) -> None:
        """P5-03: テキストおよび build_media_block で構築した画像入力ブロックと組み合わせて validate_payload() がエラー 0 件で通る。"""
        png_bytes = _make_minimal_png_bytes()
        with tempfile.TemporaryDirectory() as tmp:
            img_path = Path(tmp) / "screen.png"
            img_path.write_bytes(png_bytes)
            media_block = run_decisions.build_media_block(img_path, resolution="medium")

        self.assertEqual(media_block["type"], "image")
        self.assertEqual(media_block["mime_type"], "image/png")
        self.assertEqual(media_block["resolution"], "medium")
        self.assertEqual(base64.b64decode(media_block["data"]), png_bytes)

        payload = {
            "model": run_decisions.DEFAULT_MODEL,
            "input": [
                {"type": "text", "text": "Settings screen header and Save button"},
                media_block,
            ],
            "questions": self.preset,
        }
        errors = run_decisions.validate_payload(payload)
        self.assertEqual(errors, [])

    def test_p5_04_dry_run_cli_with_media_and_preset_succeeds(self) -> None:
        """P5-04: run_decisions.py の --media と --questions 併用 --dry-run が API キーなしで成功する。"""
        with tempfile.TemporaryDirectory() as tmp:
            img_path = Path(tmp) / "ui_capture.png"
            img_path.write_bytes(_make_minimal_png_bytes())

            stdout = io.StringIO()
            stderr = io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                code = run_decisions.main(
                    [
                        "--media",
                        str(img_path),
                        "--resolution",
                        "medium",
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
        self.assertEqual(payload["input"][0]["type"], "image")
        self.assertEqual(payload["input"][0]["resolution"], "medium")
        self.assertEqual(set(payload["questions"].keys()), set(self.preset.keys()))

    def test_p5_05_mock_api_response_formats_table_and_escalation(self) -> None:
        """P5-05: モック応答を用いた --min-confidence 0.70 --format table 実行で全 7 問と ESCALATE 判定を表出力できる。"""
        mock_response = {
            "answers": {
                "has_layout_breakage": {"type": "noul", "noul": 0.04, "confidence": 0.96},
                "has_text_truncation": {"type": "noul", "noul": 0.08, "confidence": 0.92},
                "has_redundant_lead_copy": {"type": "noul", "noul": 0.89, "confidence": 0.89},
                "has_welcome_or_guide_banner": {"type": "noul", "noul": 0.62, "confidence": 0.62},
                "has_redundant_secondary_label": {"type": "noul", "noul": 0.81, "confidence": 0.81},
                "has_verbose_dialog_or_empty_state": {"type": "noul", "noul": 0.12, "confidence": 0.88},
                "visual_clarity": {
                    "type": "score",
                    "score": 2.40,
                    "legend": {str(i): item for i, item in enumerate(EXPECTED_VISUAL_CLARITY_CRITERIA)},
                    "probabilities": {"0": 0.00, "1": 0.10, "2": 0.50, "3": 0.30, "4": 0.10},
                    "confidence": 0.50,
                },
            },
            "usage": {"total_input_tokens": 512, "total_output_tokens": 0},
        }

        def fake_opener(req, timeout=30.0):
            return _MockHTTPResponse(mock_response)

        with tempfile.TemporaryDirectory() as tmp:
            img_path = Path(tmp) / "ui_capture.png"
            img_path.write_bytes(_make_minimal_png_bytes())

            stdout = io.StringIO()
            stderr = io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                code = run_decisions.main(
                    [
                        "--media",
                        str(img_path),
                        "--resolution",
                        "medium",
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
        self.assertNotIn("ESCALATE", rows["has_layout_breakage"])
        self.assertIn("ESCALATE", rows["has_welcome_or_guide_banner"])
        self.assertIn("ESCALATE", rows["visual_clarity"])
        self.assertIn("norm=0.60", rows["visual_clarity"])
        self.assertIn("output_tokens=0", table)


if __name__ == "__main__":
    unittest.main()
