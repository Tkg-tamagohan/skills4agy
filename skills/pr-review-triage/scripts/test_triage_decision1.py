#!/usr/bin/env python3
"""triage_decision1.py の単体テスト（P3-01〜P3-13）。

外部ネットワーク通信を行わず、モック opener 注入と一時ディレクトリを用いて
ドライラン、3 区分プリラベル、dispatch_mode 抽出と後方互換、信頼度・要確認エスカレーション、
秘密情報遮断、文字数ガード、Markdown 表出力、並列実行順序保持、およびエラー時マスクを検証する。
"""

from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.parse

_SCRIPT_DIR = Path(__file__).resolve().parent
if str(_SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPT_DIR))

_DECISIONS_SCRIPTS_DIR = Path(__file__).resolve().parents[2] / "gemini-decisions-api" / "scripts"
if str(_DECISIONS_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_DECISIONS_SCRIPTS_DIR))

import run_decisions  # noqa: E402
import triage_decision1 as td  # noqa: E402


class _FakeHTTPResponse:
    def __init__(self, payload: dict[str, object]) -> None:
        self._body = json.dumps(payload, ensure_ascii=False).encode("utf-8")

    def read(self) -> bytes:
        return self._body

    def __enter__(self) -> "_FakeHTTPResponse":
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> bool:
        return False


def _run_cli(
    argv: list[str],
    *,
    opener: object | None = None,
    env: dict[str, str] | None = None,
    stdin_text: str | None = None,
) -> tuple[int, str, str]:
    stdout_buf = io.StringIO()
    stderr_buf = io.StringIO()
    with redirect_stdout(stdout_buf), redirect_stderr(stderr_buf):
        code = td.main(
            argv,
            opener=opener,  # type: ignore[arg-type]
            env=env if env is not None else {},
            stdin_text=stdin_text,
        )
    return code, stdout_buf.getvalue(), stderr_buf.getvalue()


def _make_sample_items() -> list[dict[str, object]]:
    return [
        {
            "id": "PRRT_101",
            "source": "review_thread",
            "path": "src/auth.py",
            "line": 42,
            "comment_body": "Null check is missing when user session is expired.",
            "code_snippet": "def get_user(session):\n    return session.user_id",
            "recent_commits": ["abc1234 refactor session loader"],
        },
        {
            "id": "REV_202",
            "source": "review_body",
            "path": None,
            "line": None,
            "comment_body": "Please confirm whether the new rate limit applies to admin endpoints.",
            "recent_commits": ["def5678 add rate limiter middleware"],
        },
    ]


def _make_decision_response(
    bucket: str,
    bucket_conf: float,
    human_prob: float,
    severity_score: float,
    severity_probs: dict[str, float] | None = None,
    *,
    dispatch_mode: str | None = None,
    dispatch_conf: float | None = None,
) -> dict[str, object]:
    probs = severity_probs or {"0": 0.05, "1": 0.15, "2": 0.70, "3": 0.10}
    answers: dict[str, object] = {
        "triage_bucket": {
            "type": "choice",
            "choice": bucket,
            "probabilities": {bucket: bucket_conf, "other": round(1.0 - bucket_conf, 4)},
            "confidence": bucket_conf,
        },
        "needs_human_confirmation": {
            "type": "noul",
            "noul": human_prob,
            "confidence": max(human_prob, 1.0 - human_prob),
        },
        "severity": {
            "type": "score",
            "score": severity_score,
            "legend": {str(i): label for i, label in enumerate(td.SEVERITY_CRITERIA)},
            "probabilities": probs,
            "confidence": max(probs.values()),
        },
    }
    if dispatch_mode is not None:
        dispatch_entry: dict[str, object] = {
            "type": "choice",
            "choice": dispatch_mode,
        }
        if dispatch_conf is not None:
            dispatch_entry["confidence"] = dispatch_conf
        answers["dispatch_mode"] = dispatch_entry
    return {
        "answers": answers,
        "usage": {"total_input_tokens": 180, "total_output_tokens": 0},
    }


class TestTriageDecision1(unittest.TestCase):
    def test_P3_01_dry_run_validates_payload_and_questions(self) -> None:
        """P3-01: --dry-run が API キー不要で 4 問を含む検証済みペイロード群を返す。"""
        items = _make_sample_items()
        with tempfile.TemporaryDirectory() as tmp:
            input_path = Path(tmp) / "reviews.json"
            input_path.write_text(json.dumps(items, ensure_ascii=False), encoding="utf-8")

            code, out, err = _run_cli(["--input", str(input_path), "--dry-run"], env={})
            self.assertEqual(code, 0, msg=err)
            self.assertEqual(err, "")

            report = json.loads(out)
            self.assertEqual(report["status"], "dry_run")
            self.assertEqual(report["item_count"], 2)
            self.assertEqual([entry["id"] for entry in report["items"]], ["PRRT_101", "REV_202"])

            for entry in report["items"]:
                payload = entry["payload"]
                self.assertEqual(run_decisions.validate_payload(payload), [])
                questions = payload["questions"]
                self.assertEqual(
                    set(questions.keys()),
                    {"triage_bucket", "needs_human_confirmation", "severity", "dispatch_mode"},
                )

                self.assertEqual(questions["triage_bucket"]["type"], "choice")
                self.assertEqual(
                    set(questions["triage_bucket"]["criteria"].keys()),
                    {
                        "unfixed_reproduces",
                        "partial_followup",
                        "already_resolved",
                        "needs_spec_decision",
                        "other",
                    },
                )
                self.assertEqual(questions["needs_human_confirmation"]["type"], "noul")
                self.assertEqual(
                    questions["needs_human_confirmation"]["instructions"],
                    "Does addressing or resolving this review comment require user confirmation "
                    "on specification policy or auto-resolve permission?",
                )
                self.assertEqual(questions["severity"]["type"], "score")
                self.assertEqual(
                    questions["severity"]["criteria"],
                    [
                        "0: nit or style",
                        "1: minor clarity or maintainability",
                        "2: functional bug or edge case",
                        "3: security, data loss, or concurrency defect",
                    ],
                )
                self.assertEqual(questions["dispatch_mode"]["type"], "choice")
                self.assertTrue(questions["dispatch_mode"]["instructions"].strip())
                self.assertEqual(
                    set(questions["dispatch_mode"]["criteria"].keys()),
                    {
                        "single_session",
                        "boost_deep",
                        "swarm_parallel",
                        "plan_first",
                        "other",
                    },
                )

    def test_P3_02_stdin_and_input_validation_errors(self) -> None:
        """P3-02: --stdin 入力が動作し、空配列は 0、不正入力は終了コード 2 を返す。"""
        items = [_make_sample_items()[0]]
        code_ok, out_ok, err_ok = _run_cli(
            ["--stdin", "--dry-run"],
            stdin_text=json.dumps(items, ensure_ascii=False),
        )
        self.assertEqual(code_ok, 0, msg=err_ok)
        self.assertEqual(json.loads(out_ok)["item_count"], 1)

        # 空配列は API 呼び出しせず終了コード 0
        called = False

        def fail_if_called(req: object, timeout: float = 30.0) -> object:
            nonlocal called
            called = True
            raise AssertionError("opener should not be called for empty input")

        code_empty, out_empty, _ = _run_cli(
            ["--stdin"],
            opener=fail_if_called,
            env={},
            stdin_text="[]",
        )
        self.assertEqual(code_empty, 0)
        self.assertFalse(called)
        self.assertEqual(json.loads(out_empty)["item_count"], 0)

        invalid_cases: list[tuple[list[str], str | None]] = [
            (["--dry-run"], None),
            (["--stdin", "--min-confidence", "1.5"], "[]"),
            (["--stdin"], "{}"),
            (["--stdin"], json.dumps([{"id": "1", "source": "invalid_src", "comment_body": "hi"}])),
            (["--stdin"], json.dumps([{"id": "1", "source": "review_thread", "comment_body": "  "}])),
        ]
        for argv, stdin_data in invalid_cases:
            with self.subTest(argv=argv, stdin_data=stdin_data):
                code_err, _, err_msg = _run_cli(argv, stdin_text=stdin_data)
                self.assertEqual(code_err, 2)
                self.assertTrue(err_msg.strip())

    def test_P3_03_three_bucket_prelabel_and_severity_enrichment(self) -> None:
        """P3-03: 3 区分（unfixed/partial/resolved）と仕様判断のプリラベル時に needs_deep_review=false になる。"""
        items = [
            {"id": "T1", "source": "review_thread", "path": "a.py", "line": 10, "comment_body": "Still crashes on None"},
            {"id": "T2", "source": "review_thread", "path": "b.py", "line": 20, "comment_body": "Main fix OK, check timeout"},
            {"id": "T3", "source": "review_thread", "path": "c.py", "line": 30, "comment_body": "Already fixed in commit xyz"},
            {"id": "T4", "source": "review_body", "path": None, "line": None, "comment_body": "Pick retry backoff strategy"},
        ]
        responses_by_id = {
            "T1": _make_decision_response(
                "unfixed_reproduces", 0.91, 0.12, 2.0, {"0": 0.0, "1": 0.1, "2": 0.85, "3": 0.05}
            ),
            "T2": _make_decision_response(
                "partial_followup", 0.84, 0.25, 1.2, {"0": 0.1, "1": 0.7, "2": 0.2, "3": 0.0}
            ),
            "T3": _make_decision_response(
                "already_resolved", 0.95, 0.05, 0.2, {"0": 0.85, "1": 0.15, "2": 0.0, "3": 0.0}
            ),
            "T4": _make_decision_response(
                "needs_spec_decision", 0.88, 0.40, 1.5, {"0": 0.05, "1": 0.45, "2": 0.50, "3": 0.0}
            ),
        }

        def fake_opener(req: object, timeout: float = 30.0) -> _FakeHTTPResponse:
            body = json.loads(req.data.decode("utf-8"))  # type: ignore[attr-defined]
            text = body["input"][0]["text"]
            for item_id, resp in responses_by_id.items():
                if f"Review Item ID: {item_id}\n" in text:
                    return _FakeHTTPResponse(resp)
            raise AssertionError(f"Unexpected request text: {text}")

        code, out, err = _run_cli(
            ["--stdin"],
            opener=fake_opener,
            env={"GEMINI_API_KEY": "dummy-api-key"},
            stdin_text=json.dumps(items),
        )
        self.assertEqual(code, 0, msg=err)
        report = json.loads(out)
        self.assertEqual(report["prelabeled_count"], 4)
        self.assertEqual(report["deep_review_count"], 0)

        by_id = {entry["id"]: entry for entry in report["items"]}
        self.assertEqual(by_id["T1"]["triage_bucket"], "unfixed_reproduces")
        self.assertFalse(by_id["T1"]["needs_deep_review"])
        self.assertEqual(by_id["T1"]["severity_top_level"], "2")
        self.assertEqual(by_id["T1"]["severity_label"], "2: functional bug or edge case")
        self.assertAlmostEqual(by_id["T1"]["severity_normalized"], round(2.0 / 3.0, 4))

        self.assertEqual(by_id["T2"]["triage_bucket"], "partial_followup")
        self.assertFalse(by_id["T2"]["needs_deep_review"])
        self.assertEqual(by_id["T3"]["triage_bucket"], "already_resolved")
        self.assertFalse(by_id["T3"]["needs_deep_review"])
        self.assertEqual(by_id["T4"]["triage_bucket"], "needs_spec_decision")
        self.assertFalse(by_id["T4"]["needs_deep_review"])

    def test_P3_04_escalation_on_low_confidence_other_and_human_confirmation(self) -> None:
        """P3-04: 低信頼度・other・needs_human_confirmation>=0.50 で needs_deep_review=true になる。"""
        items = [
            {"id": "BOUNDARY_OK", "source": "review_thread", "path": "a.py", "line": 1, "comment_body": "Exact boundary OK"},
            {"id": "LOW_CONF", "source": "review_thread", "path": "b.py", "line": 2, "comment_body": "Low confidence"},
            {"id": "OTHER_BUCKET", "source": "review_thread", "path": "c.py", "line": 3, "comment_body": "Other bucket"},
            {"id": "HUMAN_BOUNDARY", "source": "review_body", "path": None, "line": None, "comment_body": "Confirm policy"},
        ]
        responses = {
            "BOUNDARY_OK": _make_decision_response("already_resolved", 0.80, 0.49, 0.0),
            "LOW_CONF": _make_decision_response("already_resolved", 0.79, 0.10, 1.0),
            "OTHER_BUCKET": _make_decision_response("other", 0.99, 0.10, 1.0),
            "HUMAN_BOUNDARY": _make_decision_response("already_resolved", 0.95, 0.50, 2.0),
        }

        def fake_opener(req: object, timeout: float = 30.0) -> _FakeHTTPResponse:
            text = json.loads(req.data.decode("utf-8"))["input"][0]["text"]  # type: ignore[attr-defined]
            for item_id, resp in responses.items():
                if f"Review Item ID: {item_id}\n" in text:
                    return _FakeHTTPResponse(resp)
            raise AssertionError("Unknown item")

        code, out, err = _run_cli(
            ["--stdin"],
            opener=fake_opener,
            env={"GEMINI_API_KEY": "dummy-api-key"},
            stdin_text=json.dumps(items),
        )
        self.assertEqual(code, 0, msg=err)
        report = json.loads(out)
        self.assertEqual(report["prelabeled_count"], 1)
        self.assertEqual(report["deep_review_count"], 3)

        by_id = {entry["id"]: entry for entry in report["items"]}
        self.assertFalse(by_id["BOUNDARY_OK"]["needs_deep_review"])
        self.assertEqual(by_id["BOUNDARY_OK"]["escalation_reasons"], [])

        self.assertTrue(by_id["LOW_CONF"]["needs_deep_review"])
        self.assertIn("low_confidence", by_id["LOW_CONF"]["escalation_reasons"])

        self.assertTrue(by_id["OTHER_BUCKET"]["needs_deep_review"])
        self.assertIn("bucket_other", by_id["OTHER_BUCKET"]["escalation_reasons"])

        self.assertTrue(by_id["HUMAN_BOUNDARY"]["needs_deep_review"])
        self.assertIn("human_confirmation_required", by_id["HUMAN_BOUNDARY"]["escalation_reasons"])

    def test_P3_05_secret_detection_blocks_before_send_without_exposing_values(self) -> None:
        """P3-05: 全トークン形式と秘密鍵ヘッダを終了コード 2 で遮断し、実値を出力しない。"""
        dummy_secrets = [
            ("AIza", "AIza" + "Xy9" * 10, "comment_body"),
            ("ghp", "ghp_" + "A1b2" * 6, "code_snippet"),
            ("ghs", "ghs_" + "Z9y8" * 6, "comment_body"),
            ("github_pat", "github_pat_" + "AbCd1234_" * 3, "code_snippet"),
            ("sk", "sk-" + "projTestSecretKey1234567890", "comment_body"),
            ("AKIA", "AKIA" + "1234567890ABCDEF", "recent_commits"),
            ("pem", "-----BEGIN RSA " + "PRIVATE KEY-----\nMIIEowIBAAKCAQEA", "code_snippet"),
        ]

        called = False

        def fail_opener(req: object, timeout: float = 30.0) -> object:
            nonlocal called
            called = True
            raise AssertionError("opener must not be called when secret is detected")

        for label, secret_val, target_field in dummy_secrets:
            with self.subTest(label=label, field=target_field):
                item: dict[str, object] = {
                    "id": f"SEC_{label}",
                    "source": "review_thread",
                    "path": "src/config.py",
                    "line": 12,
                    "comment_body": "Check credential handling.",
                    "code_snippet": "x = 1",
                }
                if target_field == "recent_commits":
                    item[target_field] = [f"commit containing {secret_val}"]
                else:
                    item[target_field] = f"value={secret_val}"

                code, out, err = _run_cli(
                    ["--stdin", "--dry-run"],
                    opener=fail_opener,
                    stdin_text=json.dumps([item]),
                )
                self.assertEqual(code, 2)
                self.assertFalse(called)
                self.assertIn("secret_detected", err)
                self.assertNotIn(secret_val, out + err)

    def test_P3_06_max_chars_guard_blocks_oversized_input(self) -> None:
        """P3-06: 文字数上限超過を終了コード 2 で遮断し、秘密検査がサイズ検査に先行する。"""
        oversized_item = {
            "id": "BIG_1",
            "source": "review_thread",
            "path": "src/big.py",
            "line": 5,
            "comment_body": "Long snippet test",
            "code_snippet": "x" * 1000,
        }
        code, _, err = _run_cli(
            ["--stdin", "--dry-run", "--max-chars", "300"],
            stdin_text=json.dumps([oversized_item]),
        )
        self.assertEqual(code, 2)
        self.assertIn("input_size_limit_exceeded", err)

        # 上限超過位置の後ろに秘密値があっても secret_detected で遮断し露出しない
        secret_tail = "ghp_" + "TailSecret99" * 3
        oversized_secret = dict(oversized_item)
        oversized_secret["code_snippet"] = ("y" * 500) + secret_tail
        code2, out2, err2 = _run_cli(
            ["--stdin", "--dry-run", "--max-chars", "300"],
            stdin_text=json.dumps([oversized_secret]),
        )
        self.assertEqual(code2, 2)
        self.assertIn("secret_detected", err2)
        self.assertNotIn(secret_tail, out2 + err2)

    def test_P3_07_markdown_table_output_escapes_pipes_and_formats_summary(self) -> None:
        """P3-07: --format table が Markdown 表を出力し、パイプ文字や改行を安全に整形する。"""
        items = [
            {
                "id": "TBL|1\nline",
                "source": "review_thread",
                "path": "src/ui|view.py",
                "line": 77,
                "comment_body": "日本語コメントの確認",
            }
        ]

        def fake_opener(req: object, timeout: float = 30.0) -> _FakeHTTPResponse:
            return _FakeHTTPResponse(_make_decision_response("already_resolved", 0.93, 0.12, 0.0))

        code, out, err = _run_cli(
            ["--stdin", "--format", "table"],
            opener=fake_opener,
            env={"GEMINI_API_KEY": "dummy-api-key"},
            stdin_text=json.dumps(items, ensure_ascii=False),
        )
        self.assertEqual(code, 0, msg=err)
        self.assertIn("| id | source | location | triage_bucket | confidence |", out)
        self.assertIn("TBL\\|1 line", out)
        self.assertIn("src/ui\\|view.py:77", out)
        self.assertIn("already_resolved", out)
        self.assertIn("false", out)
        self.assertIn("summary: total=1, prelabeled=1, deep_review=0", out)

        code_dry, out_dry, err_dry = _run_cli(
            ["--stdin", "--dry-run", "--format", "table"],
            stdin_text=json.dumps(items, ensure_ascii=False),
        )
        self.assertEqual(code_dry, 0, msg=err_dry)
        self.assertIn("| id | source | location | input_chars | model | questions |", out_dry)
        self.assertIn("dry_run: item_count=1", out_dry)

    def test_P3_08_parallel_execution_preserves_input_order(self) -> None:
        """P3-08: 並列実行で完了順が逆転しても出力配列が入力順序を厳密に保持する。"""
        items = [
            {"id": "ITEM_0", "source": "review_thread", "path": "f0.py", "line": 1, "comment_body": "zero"},
            {"id": "ITEM_1", "source": "review_thread", "path": "f1.py", "line": 2, "comment_body": "one"},
            {"id": "ITEM_2", "source": "review_thread", "path": "f2.py", "line": 3, "comment_body": "two"},
            {"id": "ITEM_3", "source": "review_body", "path": None, "line": None, "comment_body": "three"},
        ]
        done_events = {f"ITEM_{i}": threading.Event() for i in range(4)}
        wait_for = {"ITEM_0": "ITEM_1", "ITEM_1": "ITEM_2", "ITEM_2": "ITEM_3"}
        seen_keys: list[str] = []
        completion_order: list[str] = []
        lock = threading.Lock()

        def staggered_opener(req: object, timeout: float = 30.0) -> _FakeHTTPResponse:
            with lock:
                seen_keys.append(req.get_header("X-goog-api-key"))  # type: ignore[attr-defined]
            text = json.loads(req.data.decode("utf-8"))["input"][0]["text"]  # type: ignore[attr-defined]
            matched_id = next(item_id for item_id in done_events if f"Review Item ID: {item_id}\n" in text)
            dep_id = wait_for.get(matched_id)
            if dep_id is not None and not done_events[dep_id].wait(timeout=2.0):
                raise TimeoutError(f"{dep_id} did not complete concurrently within timeout")
            with lock:
                completion_order.append(matched_id)
            done_events[matched_id].set()
            return _FakeHTTPResponse(_make_decision_response("partial_followup", 0.86, 0.20, 1.0))

        code, out, err = _run_cli(
            ["--stdin", "--max-workers", "4"],
            opener=staggered_opener,
            env={"GEMINI_API_KEY": "parallel-test-key"},
            stdin_text=json.dumps(items),
        )
        self.assertEqual(code, 0, msg=err)
        report = json.loads(out)
        self.assertEqual(completion_order, ["ITEM_3", "ITEM_2", "ITEM_1", "ITEM_0"])
        self.assertEqual([entry["id"] for entry in report["items"]], ["ITEM_0", "ITEM_1", "ITEM_2", "ITEM_3"])
        self.assertEqual(seen_keys, ["parallel-test-key"] * 4)

    def test_P3_09_missing_key_and_api_errors_mask_api_key(self) -> None:
        """P3-09: API キー未設定、安全遮断、API 失敗で終了コード非ゼロとなり、キー実値をマスクする。"""
        items = [_make_sample_items()[0]]
        code_no_key, _, err_no_key = _run_cli(["--stdin"], env={}, stdin_text=json.dumps(items))
        self.assertEqual(code_no_key, 2)
        self.assertIn("GEMINI_API_KEY", err_no_key)

        secret_api_key = "AIza" + "MaskTestApiKey9876543210"

        def opener_safety(req: object, timeout: float = 30.0) -> _FakeHTTPResponse:
            return _FakeHTTPResponse(
                {
                    "answers": {},
                    "prompt_feedback": {
                        "block_reason": "SAFETY",
                        "block_reason_message": f"Blocked for key={secret_api_key}",
                    },
                }
            )

        code_safety, out_safety, err_safety = _run_cli(
            ["--stdin"],
            opener=opener_safety,
            env={"GEMINI_API_KEY": secret_api_key},
            stdin_text=json.dumps(items),
        )
        self.assertEqual(code_safety, 3)
        self.assertNotIn(secret_api_key, out_safety + err_safety)
        self.assertTrue(json.loads(err_safety)["blocked"])

        def opener_http_500(req: object, timeout: float = 30.0) -> object:
            raise urllib.error.HTTPError(
                url=td.DEFAULT_ENDPOINT,
                code=500,
                msg="Internal Server Error",
                hdrs={},  # type: ignore[arg-type]
                fp=io.BytesIO(f"error with {secret_api_key}".encode("utf-8")),
            )

        code_api, out_api, err_api = _run_cli(
            ["--stdin"],
            opener=opener_http_500,
            env={"GEMINI_API_KEY": secret_api_key},
            stdin_text=json.dumps(items),
        )
        self.assertEqual(code_api, 1)
        self.assertNotIn(secret_api_key, out_api + err_api)
        self.assertIn("[REDACTED]", err_api)

    def test_P3_10_dispatch_mode_extraction_compat_and_table(self) -> None:
        """P3-10: dispatch_mode の抽出、旧応答との後方互換、および dispatch 表出力を検証する。"""
        items = [
            {"id": "DM_FULL", "source": "review_thread", "path": "src/core.py", "line": 10, "comment_body": "Deep bug"},
            {"id": "DM_MODE_ONLY", "source": "review_thread", "path": "src/util.py", "line": 20, "comment_body": "Small typo"},
            {"id": "DM_MISSING", "source": "review_body", "path": None, "line": None, "comment_body": "Legacy mock"},
            {"id": "DM_LOW_DISPATCH_CONF", "source": "review_thread", "path": "src/ok.py", "line": 30, "comment_body": "Low dispatch conf"},
        ]
        responses = {
            "DM_FULL": _make_decision_response(
                "unfixed_reproduces",
                0.91,
                0.10,
                2.0,
                dispatch_mode="boost_deep",
                dispatch_conf=0.86,
            ),
            "DM_MODE_ONLY": _make_decision_response(
                "already_resolved",
                0.92,
                0.05,
                0.0,
                dispatch_mode="single_session",
                dispatch_conf=None,
            ),
            "DM_MISSING": _make_decision_response(
                "already_resolved",
                0.89,
                0.15,
                1.0,
            ),
            "DM_LOW_DISPATCH_CONF": _make_decision_response(
                "already_resolved",
                0.94,
                0.10,
                0.0,
                dispatch_mode="other",
                dispatch_conf=0.25,
            ),
        }

        def fake_opener(req: object, timeout: float = 30.0) -> _FakeHTTPResponse:
            text = json.loads(req.data.decode("utf-8"))["input"][0]["text"]  # type: ignore[attr-defined]
            for item_id, resp in responses.items():
                if f"Review Item ID: {item_id}\n" in text:
                    return _FakeHTTPResponse(resp)
            raise AssertionError(f"Unexpected request text: {text}")

        code_json, out_json, err_json = _run_cli(
            ["--stdin"],
            opener=fake_opener,
            env={"GEMINI_API_KEY": "dummy-api-key"},
            stdin_text=json.dumps(items),
        )
        self.assertEqual(code_json, 0, msg=err_json)
        report = json.loads(out_json)
        self.assertEqual(report["prelabeled_count"], 4)
        self.assertEqual(report["deep_review_count"], 0)

        by_id = {entry["id"]: entry for entry in report["items"]}
        self.assertEqual(by_id["DM_FULL"]["dispatch_mode"], "boost_deep")
        self.assertAlmostEqual(by_id["DM_FULL"]["dispatch_confidence"], 0.86)
        self.assertFalse(by_id["DM_FULL"]["needs_deep_review"])
        self.assertEqual(by_id["DM_FULL"]["escalation_reasons"], [])

        self.assertEqual(by_id["DM_MODE_ONLY"]["dispatch_mode"], "single_session")
        self.assertIsNone(by_id["DM_MODE_ONLY"]["dispatch_confidence"])

        self.assertIsNone(by_id["DM_MISSING"]["dispatch_mode"])
        self.assertIsNone(by_id["DM_MISSING"]["dispatch_confidence"])
        self.assertFalse(by_id["DM_MISSING"]["needs_deep_review"])
        self.assertEqual(by_id["DM_MISSING"]["escalation_reasons"], [])

        # dispatch_mode="other" や低信頼度でも needs_deep_review / escalation_reasons は変わらない
        self.assertEqual(by_id["DM_LOW_DISPATCH_CONF"]["dispatch_mode"], "other")
        self.assertAlmostEqual(by_id["DM_LOW_DISPATCH_CONF"]["dispatch_confidence"], 0.25)
        self.assertFalse(by_id["DM_LOW_DISPATCH_CONF"]["needs_deep_review"])
        self.assertEqual(by_id["DM_LOW_DISPATCH_CONF"]["escalation_reasons"], [])

        # 不正型（bool の confidence、非文字列の choice）への耐性確認
        malformed_eval = td.evaluate_item_response(
            {"id": "MAL", "source": "review_thread", "path": "m.py", "line": 1},
            {
                "answers": {
                    "triage_bucket": {"choice": "already_resolved", "confidence": 0.90},
                    "needs_human_confirmation": {"noul": 0.10},
                    "dispatch_mode": {"choice": 123, "confidence": True},
                }
            },
        )
        self.assertIsNone(malformed_eval["dispatch_mode"])
        self.assertIsNone(malformed_eval["dispatch_confidence"])
        self.assertFalse(malformed_eval["needs_deep_review"])

        # Markdown 表出力で dispatch 列の順序と値・欠落時 "-" を検証する
        code_tbl, out_tbl, err_tbl = _run_cli(
            ["--stdin", "--format", "table"],
            opener=fake_opener,
            env={"GEMINI_API_KEY": "dummy-api-key"},
            stdin_text=json.dumps(items),
        )
        self.assertEqual(code_tbl, 0, msg=err_tbl)
        lines = out_tbl.splitlines()
        self.assertEqual(
            lines[0],
            "| id | source | location | triage_bucket | confidence | human_confirm | severity | dispatch | needs_deep_review | reason |",
        )
        self.assertIn("| boost_deep (0.86) |", lines[2])
        self.assertIn("| single_session |", lines[3])
        self.assertIn("| - | false | - |", lines[4])
        self.assertIn("| other (0.25) |", lines[5])

    def test_P3_11_sk_boundary_and_multiline_pem_masking(self) -> None:
        """P3-11: flask-... 等の英単語内 sk- を誤検知せず、複数行 PEM ブロックと単独ヘッダを完全マスクする。"""
        items = [
            {
                "id": "SAFE_SK",
                "source": "review_thread",
                "path": "src/app.py",
                "line": 12,
                "comment_body": "Check flask-app-secret-config-1234567890 and task-executor-worker-pool-config.",
                "code_snippet": "config_name = 'flask-app-secret-config-1234567890'",
            }
        ]
        code, out, err = _run_cli(
            ["--stdin", "--dry-run"],
            env={},
            stdin_text=json.dumps(items),
        )
        self.assertEqual(code, 0, msg=err)
        self.assertEqual(json.loads(out)["item_count"], 1)

        pem_block = (
            "-----BEGIN "
            + "RSA PRIVATE KEY-----\n"
            + "MIIEpAIBAAKCAQEAKeyBodyLine123\n"
            + "-----END "
            + "RSA PRIVATE KEY-----"
        )
        raw_secret = "key+with/secret=chars&123"
        encoded_secret = urllib.parse.quote(raw_secret, safe="")
        masked = td.mask_secret(
            f"err key={encoded_secret}\n{pem_block}\n-----BEGIN " + "PRIVATE KEY-----\npartial",
            raw_secret,
        )
        self.assertNotIn(encoded_secret, masked)
        self.assertNotIn("MIIEpAIBAAKCAQEAKeyBodyLine123", masked)
        self.assertNotIn("-----BEGIN ", masked)
        self.assertIn("[REDACTED]", masked)

    def test_P3_12_input_env_block_and_invalid_encoding_classification(self) -> None:
        """P3-12: --input .env 系を secret_env_file (exit 2) で遮断しつつ item['path']=='.env' と雛形を許容し、非 UTF-8 入力を invalid_input_encoding (exit 2) に分類する。"""
        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            env_file = tmp_dir / ".env"
            env_file.write_text("[]", encoding="utf-8")
            env_local = tmp_dir / ".env.local"
            env_local.write_text("[]", encoding="utf-8")
            env_example = tmp_dir / ".env.local.example"
            env_example.write_text(json.dumps(_make_sample_items(), ensure_ascii=False), encoding="utf-8")
            bad_utf8 = tmp_dir / "bad_cp932.json"
            bad_utf8.write_bytes(b"\x82\xa0\xff\xfe")

            for blocked_path in (env_file, env_local):
                with self.subTest(blocked_path=blocked_path.name):
                    code, out, err = _run_cli(["--input", str(blocked_path), "--dry-run"], env={})
                    self.assertEqual(code, 2)
                    self.assertEqual(out, "")
                    self.assertIn("secret_env_file", err)

            # 雛形ファイルは許容
            code_ex, out_ex, err_ex = _run_cli(["--input", str(env_example), "--dry-run"], env={})
            self.assertEqual(code_ex, 0, msg=err_ex)
            self.assertEqual(json.loads(out_ex)["item_count"], 2)

            # Promoted Fix 1: UnicodeDecodeError -> invalid_input_encoding (exit 2, not unexpected_error)
            code_enc, out_enc, err_enc = _run_cli(["--input", str(bad_utf8), "--dry-run"], env={})
            self.assertEqual(code_enc, 2)
            self.assertEqual(out_enc, "")
            self.assertIn("invalid_input_encoding", err_enc)
            self.assertNotIn("予期しないエラー", err_enc)

        # Decision F: item["path"] == ".env" は遮断しない
        env_path_item = [
            {
                "id": "ENV_META",
                "source": "review_thread",
                "path": ".env",
                "line": 1,
                "comment_body": "Remove committed .env file from tracking.",
            }
        ]
        code_meta, out_meta, err_meta = _run_cli(
            ["--stdin", "--dry-run"],
            env={},
            stdin_text=json.dumps(env_path_item),
        )
        self.assertEqual(code_meta, 0, msg=err_meta)
        self.assertEqual(json.loads(out_meta)["items"][0]["path"], ".env")

    def test_P3_13_cp932_subprocess_outputs_japanese_utf8(self) -> None:
        """P3-13: PYTHONIOENCODING=cp932 下でも日本語と cp932 非対応文字を含む --dry-run が成功する。"""
        items = [
            {
                "id": "JP-1",
                "source": "review_thread",
                "path": "src/日本語.py",
                "line": 5,
                "comment_body": "日本語コメントと絵文字 \U0001f680 の確認",
            }
        ]
        with tempfile.TemporaryDirectory() as tmp:
            input_path = Path(tmp) / "reviews.json"
            input_path.write_text(json.dumps(items, ensure_ascii=False), encoding="utf-8")

            script_path = _SCRIPT_DIR / "triage_decision1.py"
            sub_env = os.environ.copy()
            sub_env.pop("PYTHONUTF8", None)
            sub_env["PYTHONIOENCODING"] = "cp932"
            proc = subprocess.run(
                [sys.executable, str(script_path), "--input", str(input_path), "--dry-run"],
                capture_output=True,
                env=sub_env,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr.decode("utf-8", "replace"))
            parsed = json.loads(proc.stdout.decode("utf-8"))
            self.assertEqual(parsed["items"][0]["id"], "JP-1")


if __name__ == "__main__":
    unittest.main()
