#!/usr/bin/env python3
"""decision_common.py の単体テスト（テスト ID: DC-01–DC-05）。

数値判定・抽出、usage 集計、Markdown 表セル整形、エラー出力マスク、および POSIX glob 一致を検証する。
"""

from __future__ import annotations

import io
import json
from pathlib import Path
import sys
import unittest

SCRIPTS_DIR = Path(__file__).resolve().parent
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import decision_common as dc  # noqa: E402


class TestDecisionCommon(unittest.TestCase):
    def test_dc01_is_real_number_and_extract_number(self) -> None:
        """DC-01: is_real_number と extract_number が int/float を受理し、bool/None/非数値/非辞書を除外する。"""
        self.assertTrue(dc.is_real_number(0))
        self.assertTrue(dc.is_real_number(0.75))
        self.assertFalse(dc.is_real_number(True))
        self.assertFalse(dc.is_real_number(False))
        self.assertFalse(dc.is_real_number(None))
        self.assertFalse(dc.is_real_number("1.0"))

        self.assertEqual(dc.extract_number({"score": 2}, "score"), 2.0)
        self.assertEqual(dc.extract_number({"score": 0.5}, "score"), 0.5)
        self.assertIsNone(dc.extract_number({"score": True}, "score"))
        self.assertIsNone(dc.extract_number({"score": "0.5"}, "score"))
        self.assertIsNone(dc.extract_number({"other": 1}, "score"))
        self.assertIsNone(dc.extract_number(["not-a-dict"], "score"))

    def test_dc02_aggregate_usage_and_bool_exclusion(self) -> None:
        """DC-02: aggregate_usage が複数行のトークン数を合算し、usage 不在時は None、bool 混入時は無視する。"""
        self.assertIsNone(dc.aggregate_usage([{"id": "a"}, {"usage": None}]))

        rows = [
            {"usage": {"total_input_tokens": 100, "total_output_tokens": 20}},
            {"usage": {"total_input_tokens": True, "total_output_tokens": 5}},
            {"usage": {"total_input_tokens": 50, "total_output_tokens": False}},
        ]
        self.assertEqual(
            dc.aggregate_usage(rows),
            {
                "total_input_tokens": 150,
                "total_output_tokens": 25,
                "total_tokens": 175,
            },
        )

    def test_dc03_escape_md_cell_newlines_pipes_and_options(self) -> None:
        """DC-03: escape_md_cell が改行とパイプを整形し、empty と strip オプション通りに動作する。"""
        self.assertEqual(dc.escape_md_cell(None), "-")
        self.assertEqual(dc.escape_md_cell("   "), "-")
        self.assertEqual(dc.escape_md_cell("  a|b\r\nc\nd\re  "), "a\\|b c d e")
        self.assertEqual(dc.escape_md_cell(None, empty="", strip=False), "")
        self.assertEqual(dc.escape_md_cell("  a|b\nc  ", empty="", strip=False), "  a\\|b c  ")

    def test_dc04_emit_cli_error_masks_secrets_in_json_and_table(self) -> None:
        """DC-04: emit_cli_error が json と table の両形式で API キーとトークン実値を [REDACTED] にマスクする。"""
        api_key = "test-api-key-12345"
        dummy_cog = "cog_" + "AbCdEf0123456789_-XyZ"
        msg = f"failed key={api_key} token={dummy_cog}"

        json_buf = io.StringIO()
        dc.emit_cli_error("secret_detected", msg, 2, "json", api_key, stream=json_buf)
        parsed = json.loads(json_buf.getvalue())
        self.assertEqual(parsed["status"], "error")
        self.assertEqual(parsed["exit_code"], 2)
        self.assertEqual(parsed["code"], "secret_detected")
        self.assertNotIn(api_key, parsed["error"])
        self.assertNotIn(dummy_cog, parsed["error"])
        self.assertIn("[REDACTED]", parsed["error"])

        text_buf = io.StringIO()
        dc.emit_cli_error("secret_detected", msg, 2, "table", api_key, stream=text_buf)
        text_out = text_buf.getvalue()
        self.assertTrue(text_out.startswith("ERROR [secret_detected]: "))
        self.assertNotIn(api_key, text_out)
        self.assertNotIn(dummy_cog, text_out)
        self.assertIn("[REDACTED]", text_out)

    def test_dc05_normalize_and_glob_match(self) -> None:
        """DC-05: normalize_posix_rel_path、glob_to_regex、glob_match が **・*・? と区切りを正しく判定する。"""
        self.assertEqual(dc.normalize_posix_rel_path(r"  .\src\a\b.py  "), "src/a/b.py")
        self.assertEqual(dc.normalize_posix_rel_path("././foo.md"), "foo.md")

        self.assertTrue(dc.glob_match("b.py", "**/*.py"))
        self.assertTrue(dc.glob_match(r".\src\a\b.py", "src/**/*.py"))
        self.assertTrue(dc.glob_match("src/b.py", "src/**/*.py"))
        self.assertFalse(dc.glob_match("/b.py", "**/*.py"))
        self.assertFalse(dc.glob_match("src//b.py", "src/**/*.py"))

        self.assertTrue(dc.glob_match("src/ab.py", "src/a?.py"))
        self.assertFalse(dc.glob_match("src/abc.py", "src/a?.py"))
        self.assertFalse(dc.glob_match("src/a/b.py", "src/*.py"))


if __name__ == "__main__":
    unittest.main()
