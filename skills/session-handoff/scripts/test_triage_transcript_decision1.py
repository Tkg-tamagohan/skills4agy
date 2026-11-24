#!/usr/bin/env python3
"""triage_transcript_decision1.py のユニットテスト（SH-01–SH-16）。"""

from __future__ import annotations

import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import urllib.parse

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
    """SH-01–SH-16 の仕様検証テスト。"""

    def test_SH_01_load_jsonl_skips_blank_and_broken_lines(self) -> None:
        """SH-01: 空行、不正 JSON 行、非オブジェクト行を警告付きでスキップし有効行のみ読み込む。"""
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

    def test_SH_02_user_input_extracts_request_and_strips_boilerplate(self) -> None:
        """SH-02: USER_INPUT から依頼本文のみを抽出しメタデータと定型タグを除去する。"""
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

    def test_SH_03_planner_response_excludes_thinking_by_default_and_summarizes_tools(self) -> None:
        """SH-03: PLANNER_RESPONSE でツール呼び出しを要約し既定で thinking を除外する。"""
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

    def test_SH_04_generic_prioritizes_error_signals_and_truncates_normal_output(self) -> None:
        """SH-04: GENERIC ステップでエラー出力を優先保持し通常出力を短く切り詰める。"""
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

    def test_SH_05_secret_masking_removes_credentials_before_payload(self) -> None:
        """SH-05: 主要 API キー、Bearer、PEM 秘密鍵をペイロード構築前に [REDACTED] へマスクする。"""
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

    def test_SH_06_keep_recent_protects_tail_steps(self) -> None:
        """SH-06: --keep-recent 指定数だけ末尾の直近ステップを分類対象外として無条件保護する。"""
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

    def test_SH_07_budget_compression_and_chunk_splitting(self) -> None:
        """SH-07: 文字数上限とチャンク上限に従ってチャンク分割し超過時に警告を記録する。"""
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

    def test_SH_08_generated_payload_passes_run_decisions_validation(self) -> None:
        """SH-08: 生成した Decisions API ペイロードが run_decisions.validate_payload を通過する。"""
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

    def test_SH_09_classify_and_render_with_mock_api(self) -> None:
        """SH-09: モック API 応答に基づき保持、境界、除外、直近保護の件数と JSON 出力を整形する。"""
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

    def test_SH_10_dry_run_and_error_exit_codes(self) -> None:
        """SH-10: --dry-run の成功（exit 0）とキー未設定や安全遮断および API 失敗時の終了コード 3 を検証する。"""
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

    def test_SH_11_threshold_skips_api_when_below_min_steps_and_bytes(self) -> None:
        """SH-11: --min-steps と --min-bytes の双方未満なら API を呼ばず exit 0 でスキップする。"""
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

    def test_SH_12_threshold_runs_on_either_metric_and_rejects_negative(self) -> None:
        """SH-12: ステップ数またはバイト数の片方到達で実行し、負のしきい値指定を exit 2 で拒否する。"""
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

    def test_SH_13_error_outputs_mask_api_key_and_respect_sk_boundary(self) -> None:
        """SH-13: エラー出力で API キーの生値と URL エンコード値をマスクし sk- 境界を誤検知しない。"""
        raw_api_key = "key+secret/value=abc&999"
        encoded_api_key = urllib.parse.quote(raw_api_key, safe="")

        # sk- 境界: 英単語内識別子は保持され、境界付きトークンはマスクされる
        safe_ident = "flask-app-secret-config-1234567890"
        self.assertEqual(mod.mask_secrets(safe_ident), safe_ident)
        self.assertEqual(
            mod.mask_secrets(f"raw={raw_api_key} enc={encoded_api_key}", secret=raw_api_key),
            "raw=[REDACTED] enc=[REDACTED]",
        )

        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "transcript.jsonl"
            rows = [_make_row(i, content=f"msg {i}") for i in range(4)]
            p.write_text("\n".join(json.dumps(r) for r in rows), encoding="utf-8")

            def raise_safety(*_args, **_kwargs):
                raise run_decisions.SafetyBlockError(
                    "prompt_feedback",
                    "SAFETY",
                    f"blocked for key={raw_api_key} url={encoded_api_key}",
                )

            def raise_api(*_args, **_kwargs):
                raise run_decisions.ApiRequestError(
                    500, f"failed key={raw_api_key} url={encoded_api_key}"
                )

            for err_fn in (raise_safety, raise_api):
                with self.subTest(err_fn=err_fn.__name__):
                    err_buf = io.StringIO()
                    with mock.patch.dict(os.environ, {"GEMINI_API_KEY": raw_api_key}, clear=True), contextlib.redirect_stderr(err_buf):
                        rc = mod.main(["--transcript", str(p), "--keep-recent", "1"], api_caller=err_fn)
                    self.assertEqual(rc, 3)
                    err_text = err_buf.getvalue()
                    self.assertNotIn(raw_api_key, err_text)
                    self.assertNotIn(encoded_api_key, err_text)
                    self.assertIn("[REDACTED]", err_text)

            # パス解決失敗時も api_key をマスクする
            err_missing = io.StringIO()
            missing_path = Path(tmp) / f"missing_{encoded_api_key}.jsonl"
            with mock.patch.dict(os.environ, {"GEMINI_API_KEY": raw_api_key}, clear=True), contextlib.redirect_stderr(err_missing):
                rc_miss = mod.main(["--transcript", str(missing_path)])
            self.assertEqual(rc_miss, 2)
            self.assertNotIn(raw_api_key, err_missing.getvalue())
            self.assertNotIn(encoded_api_key, err_missing.getvalue())

    def test_SH_14_transcript_env_file_blocking_and_template_allowance(self) -> None:
        """SH-14: --transcript の .env 系指定を exit 2 で遮断し雛形ファイルを許容する。"""
        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            env_file = tmp_dir / ".env"
            env_file.write_text(json.dumps(_make_row(0, content="secret")) + "\n", encoding="utf-8")
            env_local = tmp_dir / ".env.local"
            env_local.write_text(json.dumps(_make_row(0, content="secret")) + "\n", encoding="utf-8")
            env_example = tmp_dir / ".env.local.example"
            env_example.write_text(json.dumps(_make_row(0, content="ok")) + "\n", encoding="utf-8")

            for blocked in (env_file, env_local):
                with self.subTest(blocked=blocked.name):
                    err_buf = io.StringIO()
                    with contextlib.redirect_stderr(err_buf):
                        rc = mod.main(["--transcript", str(blocked), "--dry-run"])
                    self.assertEqual(rc, 2)
                    self.assertIn(".env", err_buf.getvalue())

            out_buf = io.StringIO()
            with contextlib.redirect_stdout(out_buf):
                rc_ok = mod.main(["--transcript", str(env_example), "--dry-run"])
            self.assertEqual(rc_ok, 0)
            self.assertIn("Transcript Triage Dry-Run", out_buf.getvalue())

    def test_SH_15_mask_before_truncate_prevents_pem_body_leak(self) -> None:
        """SH-15: 切り詰めより先にマスクを実行し長い PEM ブロックの END 欠落による鍵露出を防ぐ。"""
        pem_secret_body = "MIIEpAIBAAKCAQEAUniqueSecretKeyBodyLine0123456789"
        long_pem_content = (
            "-----BEGIN "
            + "RSA PRIVATE KEY-----\n"
            + (pem_secret_body + "\n") * 20
            + "-----END "
            + "RSA PRIVATE KEY-----\n"
            + ("trailing normal log line\n" * 120)
        )
        for step_type in ("PLANNER_RESPONSE", "GENERIC", "USER_INPUT"):
            with self.subTest(step_type=step_type):
                content = (
                    f"<USER_REQUEST>\n{long_pem_content}\n</USER_REQUEST>"
                    if step_type == "USER_INPUT"
                    else long_pem_content
                )
                raw = _make_row(
                    10,
                    step_type=step_type,
                    content=content,
                    thinking=long_pem_content,
                    tool_calls=[{"name": "run_command", "args": {"CommandLine": long_pem_content}}],
                )
                step = mod.normalize_step(
                    raw,
                    max_step_chars=300,
                    generic_normal_chars=200,
                    include_thinking=True,
                )
                assert step is not None
                self.assertNotIn(pem_secret_body, step.normalized_text)
                self.assertNotIn("-----BEGIN ", step.normalized_text)
                self.assertNotIn(pem_secret_body, step.raw_content)
                self.assertNotIn(pem_secret_body, step.thinking_excerpt)
                self.assertNotIn(pem_secret_body, step.tool_summary)
                self.assertIn("[REDACTED]", step.normalized_text)

    def test_SH_16_main_catches_io_decode_preprocessing_errors_and_cp932_stdio(self) -> None:
        """SH-16: 読込、デコード、前処理例外をマスク済み exit 2 で処理し cp932 環境でも動作する。"""
        raw_api_key = "AIza" + "TranscriptSecretKey9876543210"
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "transcript.jsonl"
            p.write_text(json.dumps(_make_row(0, content="hello")) + "\n", encoding="utf-8")

            # OSError / UnicodeDecodeError / 前処理例外（build_chunks）を捕捉し exit 2
            for target_fn, exc_obj in (
                ("load_transcript_raw_rows", OSError(f"io failed key={raw_api_key}")),
                (
                    "load_transcript_raw_rows",
                    UnicodeDecodeError("utf-8", b"\xff", 0, 1, f"bad {raw_api_key}"),
                ),
                ("build_chunks", RuntimeError(f"preprocess failed key={raw_api_key}")),
            ):
                with self.subTest(exc=exc_obj):
                    err_buf = io.StringIO()
                    with mock.patch.dict(os.environ, {"GEMINI_API_KEY": raw_api_key}, clear=True), mock.patch.object(
                        mod, target_fn, side_effect=exc_obj
                    ), contextlib.redirect_stderr(err_buf):
                        rc = mod.main(["--transcript", str(p), "--dry-run"])
                    self.assertEqual(rc, 2)
                    self.assertNotIn(raw_api_key, err_buf.getvalue())
                    self.assertIn("[REDACTED]", err_buf.getvalue())

            # PYTHONIOENCODING=cp932 下で cp932 非対応文字を含む --dry-run が成功する
            jp_p = Path(tmp) / "jp_transcript.jsonl"
            jp_rows = [
                _make_row(0, step_type="USER_INPUT", content="<USER_REQUEST>日本語テスト</USER_REQUEST>"),
                _make_row(1, content="直近ステップ \U0001f680"),
            ]
            jp_p.write_text("\n".join(json.dumps(r, ensure_ascii=False) for r in jp_rows), encoding="utf-8")
            script_path = _THIS_DIR / "triage_transcript_decision1.py"
            sub_env = os.environ.copy()
            sub_env.pop("PYTHONUTF8", None)
            sub_env["PYTHONIOENCODING"] = "cp932"
            proc = subprocess.run(
                [
                    sys.executable,
                    str(script_path),
                    "--transcript",
                    str(jp_p),
                    "--keep-recent",
                    "1",
                    "--dry-run",
                    "--format",
                    "json",
                ],
                capture_output=True,
                env=sub_env,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr.decode("utf-8", "replace"))
            parsed = json.loads(proc.stdout.decode("utf-8"))
            self.assertIn("\U0001f680", parsed["recent"][0]["text"])


if __name__ == "__main__":
    unittest.main()
