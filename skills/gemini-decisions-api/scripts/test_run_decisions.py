#!/usr/bin/env python3
"""run_decisions.py の単体テスト（テスト ID: GD-01–GD-14）。

Gemini Decisions API 公式仕様（2026年11月版）を根拠とし、
通信部分はモックオープナー注入で決定論的に検証する。
"""

from __future__ import annotations

import base64
import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
import urllib.error

SCRIPTS_DIR = Path(__file__).resolve().parent
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import run_decisions as rd  # noqa: E402


class _MockHTTPResponse:
    def __init__(self, body: dict):
        self._bytes = json.dumps(body, ensure_ascii=False).encode("utf-8")

    def read(self) -> bytes:
        return self._bytes

    def __enter__(self) -> _MockHTTPResponse:
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        return False


class TestRunDecisions(unittest.TestCase):
    def test_gd01_valid_mixed_payload_passes(self) -> None:
        """GD-01: 有効な noul、choice、score 混在リクエストが validate_payload を通過する。"""
        payload = {
            "model": "gemini-decision-1",
            "input": [{"type": "text", "text": "注文したマグカップが割れて届きました。"}],
            "questions": {
                "is_damaged": {
                    "type": "noul",
                    "instructions": "商品は破損して届きましたか？",
                    "criteria": {
                        "true_description": "物理的に破損している",
                        "false_description": "破損していない",
                    },
                },
                "department": {
                    "type": "choice",
                    "instructions": "どの窓口が適切ですか？",
                    "criteria": {
                        "billing": "請求と返金",
                        "replacements": "交換対応",
                        "other": "その他",
                    },
                },
                "severity": {
                    "type": "score",
                    "instructions": "深刻度を評価してください。",
                    "criteria": ["軽微", "回避策あり", "業務停止"],
                },
            },
        }
        self.assertEqual(rd.validate_payload(payload), [])

    def test_gd02_bool_type_rejected_with_noul_guidance(self) -> None:
        """GD-02: type: 'bool' 指定時に noul を案内するバリデーションエラーを返す。"""
        payload = {
            "model": "gemini-decision-1",
            "input": "テスト入力",
            "questions": {
                "is_ok": {"type": "bool", "instructions": "問題ありませんか？"},
            },
        }
        errors = rd.validate_payload(payload)
        self.assertTrue(errors)
        self.assertTrue(any("noul" in err for err in errors))

    def test_gd03_invalid_question_keys_and_count_rejected(self) -> None:
        """GD-03: 質問キーの不正文字や 64 文字超過、質問数 0 件または 1,001 件以上を拒否する。"""
        empty_q = {"model": "gemini-decision-1", "input": "x", "questions": {}}
        self.assertTrue(rd.validate_payload(empty_q))

        too_many_q = {
            "model": "gemini-decision-1",
            "input": "x",
            "questions": {
                f"q_{i}": {"type": "noul", "instructions": "はい？"}
                for i in range(1001)
            },
        }
        self.assertTrue(rd.validate_payload(too_many_q))

        bad_char_q = {
            "model": "gemini-decision-1",
            "input": "x",
            "questions": {"bad key!": {"type": "noul", "instructions": "はい？"}},
        }
        self.assertTrue(rd.validate_payload(bad_char_q))

        too_long_key = {
            "model": "gemini-decision-1",
            "input": "x",
            "questions": {"a" * 65: {"type": "noul", "instructions": "はい？"}},
        }
        self.assertTrue(rd.validate_payload(too_long_key))

    def test_gd04_invalid_choice_criteria_rejected(self) -> None:
        """GD-04: choice の選択肢数不足（1 件）と選択肢キーの前後空白、制御文字、512 UTF-8 バイト超過を拒否する。"""
        cases = [
            {"only_one": "1件のみ"},
            {" leading": "先頭空白", "ok": "正常"},
            {"trailing ": "末尾空白", "ok": "正常"},
            {"bad\x07key": "制御文字", "ok": "正常"},
            {"あ" * 171: "513バイト超過", "ok": "正常"},
        ]
        for criteria in cases:
            payload = {
                "model": "gemini-decision-1",
                "input": "x",
                "questions": {
                    "route": {
                        "type": "choice",
                        "instructions": "選択してください。",
                        "criteria": criteria,
                    }
                },
            }
            with self.subTest(criteria=list(criteria.keys())):
                self.assertTrue(rd.validate_payload(payload))

    def test_gd05_invalid_score_criteria_rejected(self) -> None:
        """GD-05: score の段階数不足（1 件）と空文字列レベルを拒否する。"""
        one_level = {
            "model": "gemini-decision-1",
            "input": "x",
            "questions": {
                "sev": {"type": "score", "instructions": "評価", "criteria": ["低"]}
            },
        }
        self.assertTrue(rd.validate_payload(one_level))

        empty_level = {
            "model": "gemini-decision-1",
            "input": "x",
            "questions": {
                "sev": {"type": "score", "instructions": "評価", "criteria": ["低", "   "]}
            },
        }
        self.assertTrue(rd.validate_payload(empty_level))

    def test_gd06_invalid_inputs_rejected(self) -> None:
        """GD-06: 空の input、application/octet-stream、gs:// URI、YouTube URL を拒否する。"""
        base_q = {"q1": {"type": "noul", "instructions": "確認"}}
        invalid_inputs = [
            [],
            "",
            [{"type": "document", "data": "AA==", "mime_type": "application/octet-stream"}],
            [{"type": "video", "uri": "gs://bucket/clip.mp4", "mime_type": "video/mp4"}],
            [{"type": "video", "uri": "https://www.youtube.com/watch?v=dQw4w9WgXcQ", "mime_type": "video/mp4"}],
            [{"type": "video", "uri": "https://youtu.be/dQw4w9WgXcQ", "mime_type": "video/mp4"}],
        ]
        for inp in invalid_inputs:
            with self.subTest(inp=inp):
                self.assertTrue(
                    rd.validate_payload(
                        {"model": "gemini-decision-1", "input": inp, "questions": base_q}
                    )
                )

    def test_gd07_build_media_block_for_pdf_and_image(self) -> None:
        """GD-07: ローカル PDF および画像ファイルから document / image ブロックと resolution を正しく生成する。"""
        with tempfile.TemporaryDirectory() as tmp:
            pdf_path = Path(tmp) / "invoice.pdf"
            pdf_bytes = b"%PDF-1.4 sample"
            pdf_path.write_bytes(pdf_bytes)

            img_path = Path(tmp) / "photo.jpg"
            img_bytes = b"\xff\xd8\xff\xe0sample"
            img_path.write_bytes(img_bytes)

            pdf_block = rd.build_media_block(pdf_path)
            self.assertEqual(pdf_block["type"], "document")
            self.assertEqual(pdf_block["mime_type"], "application/pdf")
            self.assertEqual(base64.b64decode(pdf_block["data"]), pdf_bytes)
            self.assertNotIn("resolution", pdf_block)

            img_block = rd.build_media_block(img_path, resolution="low")
            self.assertEqual(img_block["type"], "image")
            self.assertEqual(img_block["mime_type"], "image/jpeg")
            self.assertEqual(img_block["resolution"], "low")
            self.assertEqual(base64.b64decode(img_block["data"]), img_bytes)

    def test_gd08_parse_inline_questions(self) -> None:
        """GD-08: インライン引数（--noul、--choice、--score）から質問マップを構築できる。"""
        questions = rd.parse_inline_questions(
            noul_specs=["is_damaged=商品は破損していますか？"],
            choice_specs=["queue=窓口を選択|billing:請求|replacements:交換|other:"],
            score_specs=["urgency=緊急度|低|中|高"],
        )
        self.assertEqual(questions["is_damaged"]["type"], "noul")
        self.assertEqual(questions["queue"]["type"], "choice")
        self.assertEqual(
            questions["queue"]["criteria"],
            {"billing": "請求", "replacements": "交換", "other": ""},
        )
        self.assertEqual(questions["urgency"]["type"], "score")
        self.assertEqual(questions["urgency"]["criteria"], ["低", "中", "高"])

    def test_gd09_dry_run_succeeds_without_api_key(self) -> None:
        """GD-09: --dry-run 実行時に GEMINI_API_KEY 未設定でもリクエスト JSON を出力して終了コード 0 を返す。"""
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = rd.main(
                [
                    "--text",
                    "注文した青いマグカップが割れて届きました。",
                    "--noul",
                    "is_damaged=商品は破損して届きましたか？",
                    "--dry-run",
                ],
                env={},
            )
        self.assertEqual(code, 0)
        self.assertEqual(stderr.getvalue(), "")
        parsed = json.loads(stdout.getvalue())
        self.assertEqual(parsed["model"], "gemini-decision-1")
        self.assertEqual(parsed["questions"]["is_damaged"]["type"], "noul")

    def test_gd10_missing_api_key_fails_nonzero(self) -> None:
        """GD-10: 本番送信時に GEMINI_API_KEY 未設定ならエラーメッセージを出して非ゼロで終了する。"""
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = rd.main(
                [
                    "--text",
                    "テスト入力",
                    "--noul",
                    "is_ok=問題ありませんか？",
                ],
                env={},
            )
        self.assertNotEqual(code, 0)
        self.assertIn("GEMINI_API_KEY", stderr.getvalue())

    def test_gd11_mock_http_200_enriches_score_and_confidence(self) -> None:
        """GD-11: モック HTTP 200 応答に対して score 正規化値と --min-confidence の needs_escalation 判定を付与する。"""
        mock_body = {
            "answers": {
                "is_defect": {"type": "noul", "noul": 0.94, "confidence": 0.94},
                "route": {
                    "type": "choice",
                    "choice": "other",
                    "probabilities": {"billing": 0.4, "other": 0.6},
                    "confidence": 0.6,
                },
                "severity": {
                    "type": "score",
                    "score": 1.5,
                    "legend": {"0": "軽微", "1": "中程度", "2": "致命的"},
                    "probabilities": {"0": 0.05, "1": 0.40, "2": 0.55},
                    "confidence": 0.55,
                },
            },
            "usage": {"total_input_tokens": 120, "total_output_tokens": 0, "total_tokens": 120},
        }

        def fake_opener(req, timeout=30.0):
            self.assertEqual(req.get_header("X-goog-api-key"), "test-key")
            return _MockHTTPResponse(mock_body)

        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = rd.main(
                [
                    "--text",
                    "左側の音が途切れます。",
                    "--noul",
                    "is_defect=ハードウェア不良ですか？",
                    "--min-confidence",
                    "0.7",
                ],
                opener=fake_opener,
                env={"GEMINI_API_KEY": "test-key"},
            )
        self.assertEqual(code, 0)
        result = json.loads(stdout.getvalue())
        self.assertFalse(result["answers"]["is_defect"]["needs_escalation"])
        self.assertTrue(result["answers"]["route"]["needs_escalation"])
        sev = result["answers"]["severity"]
        self.assertEqual(sev["top_level"], "2")
        self.assertEqual(sev["top_level_label"], "致命的")
        self.assertAlmostEqual(sev["normalized_score"], 0.75)
        self.assertTrue(sev["needs_escalation"])

    def test_gd12_http_200_prompt_feedback_block_fails_nonzero(self) -> None:
        """GD-12: HTTP 200 で prompt_feedback.block_reason が返り answers が空のとき遮断エラーとして非ゼロ終了する。"""
        blocked_body = {
            "answers": {},
            "prompt_feedback": {
                "block_reason": "safety",
                "block_reason_message": "Blocked by input safety policy.",
            },
        }

        def fake_opener(req, timeout=30.0):
            return _MockHTTPResponse(blocked_body)

        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = rd.main(
                ["--text", "blocked input", "--noul", "q1=安全ですか？"],
                opener=fake_opener,
                env={"GEMINI_API_KEY": "test-key"},
            )
        self.assertNotEqual(code, 0)
        err_payload = json.loads(stderr.getvalue())
        self.assertTrue(err_payload["blocked"])
        self.assertEqual(err_payload["source"], "prompt_feedback")
        self.assertEqual(err_payload["code"], "safety")

    def test_gd13_http_400_safety_error_fails_nonzero(self) -> None:
        """GD-13: HTTP 400 の安全フィルタ遮断 JSON（error.code: 'safety'）を受信したとき遮断理由を表示して非ゼロ終了する。"""
        err_json = {
            "error": {
                "code": "safety",
                "message": "Request blocked due to safety violations.",
            }
        }

        def fake_opener(req, timeout=30.0):
            raise urllib.error.HTTPError(
                url=rd.DEFAULT_ENDPOINT,
                code=400,
                msg="Bad Request",
                hdrs={},
                fp=io.BytesIO(json.dumps(err_json).encode("utf-8")),
            )

        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = rd.main(
                ["--text", "unsafe input", "--noul", "q1=安全ですか？"],
                opener=fake_opener,
                env={"GEMINI_API_KEY": "test-key"},
            )
        self.assertNotEqual(code, 0)
        err_payload = json.loads(stderr.getvalue())
        self.assertTrue(err_payload["blocked"])
        self.assertEqual(err_payload["source"], "http_400")
        self.assertEqual(err_payload["code"], "safety")

    def test_gd14_table_format_outputs_multibyte_utf8(self) -> None:
        """GD-14: --format table 指定時にマルチバイト文字列を含む判定結果を表形式で UTF-8 出力できる。"""
        mock_body = {
            "answers": {
                "is_damaged": {"type": "noul", "noul": 0.98, "confidence": 0.98},
                "queue": {
                    "type": "choice",
                    "choice": "交換窓口",
                    "probabilities": {"請求窓口": 0.02, "交換窓口": 0.98},
                    "confidence": 0.98,
                },
                "severity": {
                    "type": "score",
                    "score": 1.80,
                    "legend": {"0": "軽微", "1": "中程度", "2": "即時対応"},
                    "probabilities": {"0": 0.02, "1": 0.16, "2": 0.82},
                    "confidence": 0.82,
                },
            },
            "usage": {"total_input_tokens": 95, "total_output_tokens": 0},
        }

        def fake_opener(req, timeout=30.0):
            return _MockHTTPResponse(mock_body)

        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = rd.main(
                [
                    "--text",
                    "青いマグカップが割れて届きました。",
                    "--noul",
                    "is_damaged=破損していますか？",
                    "--format",
                    "table",
                ],
                opener=fake_opener,
                env={"GEMINI_API_KEY": "test-key"},
            )
        self.assertEqual(code, 0)
        table = stdout.getvalue()
        self.assertIn("| question | type | value | confidence | extra |", table)
        self.assertIn("交換窓口", table)
        self.assertIn("即時対応", table)
        self.assertIn("output_tokens=0", table)


if __name__ == "__main__":
    unittest.main()
