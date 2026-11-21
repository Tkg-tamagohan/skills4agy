#!/usr/bin/env python3
"""triage_transcript_decision1.py のユニットテスト（T01–T12）。"""

from __future__ import annotations

import contextlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

_THIS_DIR = Path(__file__).resolve().parent
if str(_THIS_DIR) not in sys.path:
    sys.path.insert(0, str(_THIS_DIR))

import triage_transcript_decision1 as mod  # noqa: E402
import run_decisions  # noqa: E402


def _make_row(
    step_index: int,
    *,
    step_type: str = "PLANNER_RESPONSE",
    source: str = "MODEL",
    status: str = "DONE",
    content: str = "",
    thinking: str = "",
    tool_calls: list[dict] | None = None,
) -> dict:
    row: dict = {
        "step_index": step_index,
        "source": source,
        "type": step_type,
        "status": status,
        "created_at": "2026-11-21T01:00:00Z",
    }
    if content:
        row["content"] = content
    if thinking:
        row["thinking"] = thinking
    if tool_calls is not None:
        row["tool_calls"] = tool_calls
    return row


class TestTriageTranscriptDecision1(unittest.TestCase):
    """T01–T12 の仕様検証テスト。"""

    def test_T01_load_jsonl_skips_blank_and_broken_lines(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "transcript.jsonl"
            lines = [
                json.dumps(_make_row(0, step_type="USER_INPUT", content="hello")),
                "",
                "not a json line {",
                json.dumps(["array-not-object"]),
                json.dumps(_make_row(1, content="world")),
            ]
            p.write_text("\n".join(lines), encoding="utf-8")
            rows, warnings = mod.load_transcript_raw_rows(p)
            self.assertEqual(len(rows), 2)
            self.assertEqual([r["step_index"] for r in rows], [0, 1])
            self.assertEqual(len(warnings), 2)

    def test_T02_user_input_extracts_request_and_strips_boilerplate(self) -> None:
        raw = _make_row(
            0,
            step_type="USER_INPUT",
            source="USER_EXPLICIT",
            content=(
                "<USER_REQUEST>\n本番実装の前提を確認してください。\n</USER_REQUEST>\n"
                "<ADDITIONAL_METADATA>\nlocal time: 2026-11-21\n<PLAN>huge plan</PLAN>\n</ADDITIONAL_METADATA>\n"
                "<USER_SETTINGS_CHANGE>Model changed</USER_SETTINGS_CHANGE>"
            ),
        )
        step = mod.normalize_step(raw)
        assert step is not None
        self.assertEqual(step.normalized_text, "本番実装の前提を確認してください。")
        self.assertNotIn("ADDITIONAL_METADATA", step.normalized_text)
        self.assertNotIn("huge plan", step.normalized_text)

    def test_T03_planner_response_excludes_thinking_by_default_and_summarizes_tools(self) -> None:
        raw = _make_row(
            3,
            step_type="PLANNER_RESPONSE",
            content="設定ファイルを確認します。",
            thinking="Internal secret chain of thought",
            tool_calls=[
                {"name": "read_file", "args": {"Path": '"C:\\repo\\plugin.json"'}},
                {"name": "run_command", "args": {"CommandLine": "git status -s"}},
            ],
        )
        step_default = mod.normalize_step(raw, include_thinking=False)
        assert step_default is not None
        self.assertIn("設定ファイルを確認します。", step_default.normalized_text)
        self.assertIn("read_file(Path=C:\\repo\\plugin.json)", step_default.normalized_text)
        self.assertIn("run_command(CommandLine=git status -s)", step_default.normalized_text)
        self.assertNotIn("Internal secret chain of thought", step_default.normalized_text)

        step_with_thinking = mod.normalize_step(raw, include_thinking=True)
        assert step_with_thinking is not None
        self.assertIn("[thinking] Internal secret chain of thought", step_with_thinking.normalized_text)

    def test_T04_generic_prioritizes_error_signals_and_truncates_normal_output(self) -> None:
        long_normal = "Created At: 2026-11-21\n" + ("normal line\n" * 100)
        long_error = (
            "Created At: 2026-11-21\n"
            "Command exited with code 1\n"
            + ("stack frame detail\n" * 60)
            + "AssertionError: expected 200 got 500"
        )
        normal_step = mod.normalize_step(_make_row(4, step_type="GENERIC", content=long_normal))
        error_step = mod.normalize_step(_make_row(5, step_type="GENERIC", content=long_error))
        assert normal_step is not None and error_step is not None

        self.assertFalse(normal_step.is_error_signal)
        self.assertTrue(error_step.is_error_signal)
        self.assertLessEqual(len(normal_step.normalized_text), mod.DEFAULT_GENERIC_NORMAL_CHARS + 20)
        self.assertGreater(len(error_step.normalized_text), len(normal_step.normalized_text))
        self.assertIn("AssertionError: expected 200 got 500", error_step.normalized_text)

    def test_T05_secret_masking_removes_credentials_before_payload(self) -> None:
        secret_content = (
            "google=AIzaSyDummyKeyValue1234567890abcd\n"
            "github=ghp_1234567890abcdefghijklmnop\n"
            "openai=sk-proj1234567890abcdefghijklmnop\n"
            "aws=AKIAIOSFODNN7EXAMPLE\n"
            "auth=Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload\n"
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA\n-----END RSA PRIVATE KEY-----"
        )
        step = mod.normalize_step(_make_row(2, step_type="GENERIC", content=secret_content))
        assert step is not None
        payload = mod.build_decision_payload([step])
        serialized = json.dumps(payload, ensure_ascii=False)
        for leaked in (
            "AIzaSyDummy",
            "ghp_123456",
            "sk-proj123",
            "AKIAIOSFODNN7EXAMPLE",
            "eyJhbGci",
            "MIIEpAIBAAKCAQEA",
        ):
            self.assertNotIn(leaked, serialized)
        self.assertIn("[REDACTED]", serialized)

    def test_T06_keep_recent_protects_tail_steps(self) -> None:
        rows = [_make_row(i, content=f"step body {i}") for i in range(10)]
        chunks, recent, warnings, truncated = mod.build_chunks(
            rows,
            keep_recent=4,
            max_chars=240_000,
            max_chunks=4,
            max_step_chars=1200,
            include_thinking=False,
        )
        self.assertEqual([s.step_index for s in recent], [6, 7, 8, 9])
        self.assertEqual(len(chunks), 1)
        self.assertEqual([s.step_index for s in chunks[0]], [0, 1, 2, 3, 4, 5])
        self.assertEqual(truncated, 0)
        self.assertEqual(warnings, [])

    def test_T07_budget_compression_and_chunk_splitting(self) -> None:
        rows = [
            _make_row(i, step_type="GENERIC", content=f"step {i} " + ("x" * 600))
            for i in range(30)
        ]
        chunks, recent, warnings, truncated = mod.build_chunks(
            rows,
            keep_recent=2,
            max_chars=1000,
            max_chunks=2,
            max_step_chars=1200,
            include_thinking=False,
        )
        self.assertEqual(len(recent), 2)
        self.assertEqual(len(chunks), 2)
        self.assertGreater(truncated, 0)
        self.assertTrue(any("チャンク数が上限" in w for w in warnings))
        for ch in chunks:
            self.assertLessEqual(len(ch), mod.MAX_QUESTIONS_PER_REQUEST)

    def test_T08_generated_payload_passes_run_decisions_validation(self) -> None:
        rows = [
            _make_row(0, step_type="USER_INPUT", content="<USER_REQUEST>要件確認</USER_REQUEST>"),
            _make_row(1, step_type="PLANNER_RESPONSE", content="方針を確定しました。"),
            _make_row(2, step_type="GENERIC", content="Command exited with code 1\nFAILED"),
        ]
        steps = [s for r in rows if (s := mod.normalize_step(r)) is not None]
        payload = mod.build_decision_payload(steps)
        errors = run_decisions.validate_payload(payload)
        self.assertEqual(errors, [])
        self.assertEqual(set(payload["questions"].keys()), {"step_0000", "step_0001", "step_0002"})

    def test_T09_classify_and_render_with_mock_api(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "transcript.jsonl"
            rows = [
                _make_row(0, step_type="USER_INPUT", content="<USER_REQUEST>仕様を決めたい</USER_REQUEST>"),
                _make_row(1, content="仕様 A を採用します。"),
                _make_row(2, step_type="GENERIC", content="Command exited with code 1\nmissing env"),
                _make_row(3, content="src/app.py を修正済み。次はテスト追加。"),
                _make_row(4, step_type="GENERIC", content="README の中身..."),
                _make_row(5, content="曖昧な中間メモ"),
                _make_row(6, content="直近の応答"),
            ]
            p.write_text("\n".join(json.dumps(r, ensure_ascii=False) for r in rows), encoding="utf-8")

            def fake_api(payload: dict, **_kwargs) -> dict:
                return {
                    "answers": {
                        "step_0000": {"type": "choice", "choice": "drop_noise", "confidence": 0.90},
                        "step_0001": {"type": "choice", "choice": "keep_decision", "confidence": 0.92},
                        "step_0002": {"type": "choice", "choice": "keep_gotcha", "confidence": 0.88},
                        "step_0003": {"type": "choice", "choice": "keep_state", "confidence": 0.85},
                        "step_0004": {"type": "choice", "choice": "drop_noise", "confidence": 0.95},
                        "step_0005": {"type": "choice", "choice": "drop_noise", "confidence": 0.55},
                    }
                }

            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = mod.main(
                    ["--transcript", str(p), "--keep-recent", "1", "--format", "json"],
                    api_caller=fake_api,
                )
            self.assertEqual(rc, 0)
            data = json.loads(buf.getvalue())
            self.assertEqual(data["meta"]["kept_steps"], 3)
            self.assertEqual(data["meta"]["borderline_steps"], 1)
            self.assertEqual(data["meta"]["dropped_steps"], 2)
            self.assertEqual(data["meta"]["recent_steps"], 1)
            self.assertEqual([x["step_index"] for x in data["borderline"]], [5])

    def test_T10_dry_run_and_error_exit_codes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "transcript.jsonl"
            rows = [_make_row(i, content=f"message {i}") for i in range(4)]
            p.write_text("\n".join(json.dumps(r) for r in rows), encoding="utf-8")

            # dry-run は API キー不要で exit 0
            out_buf = io.StringIO()
            with mock.patch.dict(os.environ, {}, clear=True), contextlib.redirect_stdout(out_buf):
                rc_dry = mod.main(["--transcript", str(p), "--keep-recent", "1", "--dry-run"])
            self.assertEqual(rc_dry, 0)
            self.assertIn("ペイロード検証: OK", out_buf.getvalue())

            # API キー未設定時は exit 3
            err_buf = io.StringIO()
            with mock.patch.dict(os.environ, {}, clear=True), contextlib.redirect_stderr(err_buf):
                rc_nokey = mod.main(["--transcript", str(p), "--keep-recent", "1"])
            self.assertEqual(rc_nokey, 3)
            self.assertIn("GEMINI_API_KEY", err_buf.getvalue())

            # SafetyBlockError 時は exit 3
            def raise_safety(*_args, **_kwargs):
                raise run_decisions.SafetyBlockError("prompt_feedback", "SAFETY", "blocked")

            err_buf2 = io.StringIO()
            with contextlib.redirect_stderr(err_buf2):
                rc_safety = mod.main(
                    ["--transcript", str(p), "--keep-recent", "1"],
                    api_caller=raise_safety,
                )
            self.assertEqual(rc_safety, 3)
            self.assertIn("安全フィルタ", err_buf2.getvalue())

            # ApiRequestError 時は exit 3
            def raise_api(*_args, **_kwargs):
                raise run_decisions.ApiRequestError(503, "service unavailable")

            err_buf3 = io.StringIO()
            with contextlib.redirect_stderr(err_buf3):
                rc_api = mod.main(
                    ["--transcript", str(p), "--keep-recent", "1"],
                    api_caller=raise_api,
                )
            self.assertEqual(rc_api, 3)
            self.assertIn("呼び出しに失敗", err_buf3.getvalue())

    def test_T11_threshold_skips_api_when_below_min_steps_and_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "transcript.jsonl"
            rows = [_make_row(i, content=f"short message {i}") for i in range(5)]
            p.write_text("\n".join(json.dumps(r) for r in rows), encoding="utf-8")

            def fail_if_called(*_args, **_kwargs):
                raise AssertionError("API should not be called below threshold")

            md_buf = io.StringIO()
            with mock.patch.dict(os.environ, {}, clear=True), contextlib.redirect_stdout(md_buf):
                rc_md = mod.main(
                    ["--transcript", str(p), "--min-steps", "80", "--min-bytes", "150000"],
                    api_caller=fail_if_called,
                )
            self.assertEqual(rc_md, 0)
            md_out = md_buf.getvalue()
            self.assertIn("Skipped Below Threshold", md_out)
            self.assertIn("有効ステップ数: 5 件", md_out)
            self.assertIn("API 呼び出し: 0 回", md_out)
            self.assertIn("--min-steps", md_out)

            json_buf = io.StringIO()
            with mock.patch.dict(os.environ, {}, clear=True), contextlib.redirect_stdout(json_buf):
                rc_json = mod.main(
                    [
                        "--transcript",
                        str(p),
                        "--min-steps",
                        "80",
                        "--min-bytes",
                        "150000",
                        "--format",
                        "json",
                    ],
                    api_caller=fail_if_called,
                )
            self.assertEqual(rc_json, 0)
            data = json.loads(json_buf.getvalue())
            self.assertTrue(data["meta"]["skipped_below_threshold"])
            self.assertFalse(data["meta"]["dry_run"])
            self.assertEqual(data["meta"]["api_calls"], 0)
            self.assertEqual(data["meta"]["transcript_steps"], 5)
            self.assertGreater(data["meta"]["transcript_bytes"], 0)
            self.assertEqual(data["meta"]["min_steps"], 80)
            self.assertEqual(data["meta"]["min_bytes"], 150000)

            dry_buf = io.StringIO()
            with mock.patch.dict(os.environ, {}, clear=True), contextlib.redirect_stdout(dry_buf):
                rc_dry = mod.main(
                    [
                        "--transcript",
                        str(p),
                        "--min-steps",
                        "80",
                        "--min-bytes",
                        "150000",
                        "--dry-run",
                        "--format",
                        "json",
                    ],
                    api_caller=fail_if_called,
                )
            self.assertEqual(rc_dry, 0)
            dry_data = json.loads(dry_buf.getvalue())
            self.assertTrue(dry_data["meta"]["dry_run"])
            self.assertTrue(dry_data["meta"]["skipped_below_threshold"])

    def test_T12_threshold_runs_on_either_metric_and_rejects_negative(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            small_p = Path(tmp) / "small.jsonl"
            small_rows = [_make_row(i, content=f"msg {i}") for i in range(5)]
            small_p.write_text("\n".join(json.dumps(r) for r in small_rows), encoding="utf-8")

            large_p = Path(tmp) / "large_bytes.jsonl"
            large_rows = [_make_row(i, content=f"step {i} " + ("a" * 500)) for i in range(3)]
            large_p.write_text("\n".join(json.dumps(r) for r in large_rows), encoding="utf-8")
            self.assertGreaterEqual(large_p.stat().st_size, 1000)

            api_calls: list[int] = []

            def fake_api(payload: dict, **_kwargs) -> dict:
                api_calls.append(len(payload["questions"]))
                return {
                    "answers": {
                        qkey: {"type": "choice", "choice": "keep_decision", "confidence": 0.90}
                        for qkey in payload["questions"]
                    }
                }

            # ケース A: ステップ数のみ到達（5 >= 5, bytes < 50000）-> 実行
            buf_a = io.StringIO()
            with contextlib.redirect_stdout(buf_a):
                rc_a = mod.main(
                    [
                        "--transcript",
                        str(small_p),
                        "--keep-recent",
                        "1",
                        "--min-steps",
                        "5",
                        "--min-bytes",
                        "50000",
                        "--format",
                        "json",
                    ],
                    api_caller=fake_api,
                )
            self.assertEqual(rc_a, 0)
            data_a = json.loads(buf_a.getvalue())
            self.assertFalse(data_a["meta"]["skipped_below_threshold"])
            self.assertEqual(data_a["meta"]["api_calls"], 1)

            # ケース B: バイト数のみ到達（3 < 80, bytes >= 1000）-> 実行
            buf_b = io.StringIO()
            with contextlib.redirect_stdout(buf_b):
                rc_b = mod.main(
                    [
                        "--transcript",
                        str(large_p),
                        "--keep-recent",
                        "1",
                        "--min-steps",
                        "80",
                        "--min-bytes",
                        "1000",
                        "--format",
                        "json",
                    ],
                    api_caller=fake_api,
                )
            self.assertEqual(rc_b, 0)
            data_b = json.loads(buf_b.getvalue())
            self.assertFalse(data_b["meta"]["skipped_below_threshold"])
            self.assertEqual(data_b["meta"]["api_calls"], 1)

            # ケース C: 片側指定のみ（--min-steps 10 でスキップ / --min-bytes 100 で実行）
            buf_c1 = io.StringIO()
            with contextlib.redirect_stdout(buf_c1):
                rc_c1 = mod.main(
                    ["--transcript", str(small_p), "--min-steps", "10", "--format", "json"],
                    api_caller=fake_api,
                )
            self.assertEqual(rc_c1, 0)
            self.assertTrue(json.loads(buf_c1.getvalue())["meta"]["skipped_below_threshold"])

            buf_c2 = io.StringIO()
            with contextlib.redirect_stdout(buf_c2):
                rc_c2 = mod.main(
                    [
                        "--transcript",
                        str(small_p),
                        "--keep-recent",
                        "1",
                        "--min-bytes",
                        "100",
                        "--format",
                        "json",
                    ],
                    api_caller=fake_api,
                )
            self.assertEqual(rc_c2, 0)
            self.assertFalse(json.loads(buf_c2.getvalue())["meta"]["skipped_below_threshold"])

            # ケース D: 無指定（既定 0, 0）なら小ファイルでも実行（後方互換）
            self.assertEqual(len(api_calls), 3)
            buf_d = io.StringIO()
            with contextlib.redirect_stdout(buf_d):
                rc_d = mod.main(
                    ["--transcript", str(small_p), "--keep-recent", "1", "--format", "json"],
                    api_caller=fake_api,
                )
            self.assertEqual(rc_d, 0)
            self.assertEqual(len(api_calls), 4)

            # ケース E: 負値拒否
            for bad_flag in (["--min-steps", "-1"], ["--min-bytes", "-1"]):
                err_buf = io.StringIO()
                with contextlib.redirect_stderr(err_buf):
                    rc_bad = mod.main(["--transcript", str(small_p), *bad_flag])
                self.assertEqual(rc_bad, 2)
                self.assertIn("0 以上", err_buf.getvalue())


if __name__ == "__main__":
    unittest.main()
