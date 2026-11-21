#!/usr/bin/env python3
"""screen_tests_decision1.py の仕様準拠単体テスト（P4-01〜P4-13）。

外部ネットワーク通信を行わず、opener モック注入・--dry-run・threading.Event に
よる決定論的並列同期を用いて保護対象フィルタ CLI の仕様を検証する。
"""

from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import io
import json
import os
from pathlib import Path
import re
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

_DECISIONS_DIR = Path(__file__).resolve().parents[2] / "gemini-decisions-api" / "scripts"
if str(_DECISIONS_DIR) not in sys.path:
    sys.path.insert(0, str(_DECISIONS_DIR))

import run_decisions  # noqa: E402
import screen_tests_decision1 as screener  # noqa: E402

NEGATIVE_PHRASING_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\b(?:not|isn't|aren't|doesn't|don't|didn't|won't|can't|never)\b", re.IGNORECASE),
    re.compile(r"(?:ないか|ではないか|ませんか)"),
)


class _FakeHTTPResponse:
    def __init__(self, payload: dict[str, object]) -> None:
        self._body = json.dumps(payload, ensure_ascii=False).encode("utf-8")

    def read(self) -> bytes:
        return self._body

    def __enter__(self) -> "_FakeHTTPResponse":
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        return None


def _make_candidate(
    cand_id: str = "T-01",
    file: str = "tests/test_sample.py",
    line: int = 10,
    test_name: str = "test_sample_behavior",
    code: str = "def test_sample_behavior():\n    assert 1 + 1 == 2\n",
    git_log: object | None = None,
    spec_refs: object | None = None,
) -> dict[str, object]:
    item: dict[str, object] = {
        "id": cand_id,
        "file": file,
        "line": line,
        "test_name": test_name,
        "code": code,
    }
    if git_log is not None:
        item["git_log"] = git_log
    if spec_refs is not None:
        item["spec_refs"] = spec_refs
    return item


def _make_answers(
    *,
    prot_scores: dict[str, float] | None = None,
    category: str = "auto_prune_candidate",
    cat_confidence: float = 0.90,
    omit_prot: set[str] | None = None,
    input_tokens: int = 120,
) -> dict[str, object]:
    scores = {k: 0.10 for k in screener.PROTECTION_QUESTION_KEYS}
    if prot_scores:
        scores.update(prot_scores)
    omit = omit_prot or set()
    answers: dict[str, object] = {}
    for k, val in scores.items():
        if k in omit:
            continue
        answers[k] = {
            "type": "noul",
            "noul": val,
            "confidence": round(max(val, 1.0 - val), 4),
        }
    answers["pruning_category"] = {
        "type": "choice",
        "choice": category,
        "confidence": cat_confidence,
    }
    return {
        "answers": answers,
        "usage": {
            "total_input_tokens": input_tokens,
            "total_output_tokens": 0,
            "total_tokens": input_tokens,
        },
    }


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
        code = screener.main(
            argv,
            opener=opener,  # type: ignore[arg-type]
            env={} if env is None else env,
            stdin_text=stdin_text,
        )
    return code, stdout_buf.getvalue(), stderr_buf.getvalue()


class TestScreenTestsDecision1(unittest.TestCase):
    def test_P4_01_dry_run_validates_six_affirmative_questions(self) -> None:
        """P4-01: --dry-run はキー不要で 1 リクエスト 6 問の検証済みペイロードを出力する。"""
        candidates = [
            _make_candidate(
                cand_id="T-AUTH-01",
                file="tests/test_auth.py",
                line=42,
                test_name="test_reject_expired_token",
                code="def test_reject_expired_token():\n    assert verify('expired') is False\n",
                git_log="fix(auth): reject expired JWT (#128)",
                spec_refs=["AUTH-01"],
            )
        ]
        with tempfile.TemporaryDirectory() as tmp:
            input_path = Path(tmp) / "candidates.json"
            input_path.write_text(json.dumps(candidates, ensure_ascii=False), encoding="utf-8")

            code, out, err = _run_cli(["--input", str(input_path), "--dry-run"], env={})
            self.assertEqual(code, 0)
            self.assertEqual(err, "")
            data = json.loads(out)
            self.assertEqual(data["status"], "dry_run")
            self.assertEqual(data["total"], 1)

            payload = data["items"][0]["payload"]
            self.assertEqual(payload["model"], run_decisions.DEFAULT_MODEL)
            self.assertEqual(run_decisions.validate_payload(payload), [])

            questions = payload["questions"]
            self.assertEqual(len(questions), 6)
            for p_key in screener.PROTECTION_QUESTION_KEYS:
                self.assertIn(p_key, questions)
                self.assertEqual(questions[p_key]["type"], "noul")
            self.assertIn("pruning_category", questions)
            self.assertEqual(questions["pruning_category"]["type"], "choice")
            self.assertEqual(
                set(questions["pruning_category"]["criteria"].keys()),
                {"keep_protected", "auto_prune_candidate", "needs_discussion", "other"},
            )

            for q_key, q_body in questions.items():
                self.assertRegex(q_key, run_decisions.QUESTION_KEY_RE)
                instr = q_body["instructions"]
                for pat in NEGATIVE_PHRASING_PATTERNS:
                    self.assertIsNone(
                        pat.search(instr),
                        f"{q_key} の instructions に否定疑問語が含まれています: {instr}",
                    )

            code_tbl, out_tbl, err_tbl = _run_cli(
                ["--input", str(input_path), "--dry-run", "--format", "table"], env={}
            )
            self.assertEqual(code_tbl, 0)
            self.assertEqual(err_tbl, "")
            self.assertIn("| id | location | test_name | questions | status |", out_tbl)
            self.assertIn("T-AUTH-01", out_tbl)
            self.assertIn("Summary: dry_run total=1", out_tbl)

    def test_P4_02_stdin_utf8_and_source_exclusivity(self) -> None:
        """P4-02: --stdin で日本語を含む候補を読み込め、入力元未指定/重複指定は終了コード 2。"""
        candidates = [
            _make_candidate(
                cand_id="T-JP-01",
                file="tests/test_billing.py",
                line=15,
                test_name="test_消費税端数切り捨て",
                code="def test_消費税端数切り捨て():\n    assert calc_tax(105) == 10\n",
                git_log="fix: 消費税の切り捨て境界を修正",
                spec_refs="BILL-03",
            )
        ]
        stdin_payload = json.dumps(candidates, ensure_ascii=False)

        code, out, err = _run_cli(["--stdin", "--dry-run"], env={}, stdin_text=stdin_payload)
        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        parsed = json.loads(out)
        self.assertEqual(parsed["items"][0]["test_name"], "test_消費税端数切り捨て")
        self.assertEqual(
            run_decisions.validate_payload(parsed["items"][0]["payload"]), []
        )

        # サブプロセス実起動で --stdin と UTF-8 出力を検証
        script_path = Path(__file__).resolve().parent / "screen_tests_decision1.py"
        sub_env = os.environ.copy()
        sub_env["PYTHONUTF8"] = "1"
        sub_env["PYTHONIOENCODING"] = "utf-8"
        sub_env.pop("GEMINI_API_KEY", None)
        proc = subprocess.run(
            [sys.executable, str(script_path), "--stdin", "--dry-run"],
            input=stdin_payload,
            capture_output=True,
            text=True,
            encoding="utf-8",
            env=sub_env,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(json.loads(proc.stdout)["items"][0]["id"], "T-JP-01")

        # 入力元未指定・重複指定は終了コード 2
        code_none, _, _ = _run_cli(["--dry-run"], env={})
        self.assertEqual(code_none, 2)
        code_both, _, _ = _run_cli(
            ["--input", "dummy.json", "--stdin", "--dry-run"], env={}, stdin_text="[]"
        )
        self.assertEqual(code_both, 2)

    def test_P4_03_safety_bias_skip_keep_overrides_auto_prune_candidate(self) -> None:
        """P4-03: 保護対象 5 条件のいずれかが noul >= 0.65 なら auto_prune_candidate より優先し skip_keep。"""
        for prot_key in screener.PROTECTION_QUESTION_KEYS:
            with self.subTest(prot_key=prot_key):
                resp = _make_answers(
                    prot_scores={prot_key: 0.65},
                    category="auto_prune_candidate",
                    cat_confidence=0.99,
                )

                def fake_opener(req: object, timeout: float = 30.0) -> _FakeHTTPResponse:
                    return _FakeHTTPResponse(resp)

                code, out, err = _run_cli(
                    ["--stdin"],
                    opener=fake_opener,
                    env={"GEMINI_API_KEY": "dummy-key"},
                    stdin_text=json.dumps([_make_candidate(cand_id=f"T-{prot_key}")]),
                )
                self.assertEqual(code, 0, err)
                res = json.loads(out)["results"][0]
                self.assertEqual(res["action"], "skip_keep")
                self.assertIn(prot_key, res["triggered_protections"])

        # pruning_category == keep_protected かつ confidence >= 0.75 でも skip_keep
        keep_resp = _make_answers(
            prot_scores={k: 0.20 for k in screener.PROTECTION_QUESTION_KEYS},
            category="keep_protected",
            cat_confidence=0.75,
        )
        code2, out2, err2 = _run_cli(
            ["--stdin"],
            opener=lambda req, timeout=30.0: _FakeHTTPResponse(keep_resp),
            env={"GEMINI_API_KEY": "dummy-key"},
            stdin_text=json.dumps([_make_candidate(cand_id="T-KEEP-CHOICE")]),
        )
        self.assertEqual(code2, 0, err2)
        self.assertEqual(json.loads(out2)["results"][0]["action"], "skip_keep")

    def test_P4_04_verify_for_prune_when_all_prot_below_040_and_high_confidence(self) -> None:
        """P4-04: auto_prune_candidate かつ全保護対象 noul < 0.40 かつ confidence >= 0.80 で verify_for_prune。"""
        resp = _make_answers(
            prot_scores={k: 0.39 for k in screener.PROTECTION_QUESTION_KEYS},
            category="auto_prune_candidate",
            cat_confidence=0.80,
        )
        code, out, err = _run_cli(
            ["--stdin"],
            opener=lambda req, timeout=30.0: _FakeHTTPResponse(resp),
            env={"GEMINI_API_KEY": "dummy-key"},
            stdin_text=json.dumps([_make_candidate(cand_id="T-PRUNE-01")]),
        )
        self.assertEqual(code, 0, err)
        data = json.loads(out)
        self.assertEqual(data["summary"]["verify_for_prune"], 1)
        self.assertEqual(data["results"][0]["action"], "verify_for_prune")

    def test_P4_05_review_for_discussion_on_low_conf_borderline_and_discussion(self) -> None:
        """P4-05: 低信頼度・境界域・needs_discussion・other・欠損時は安全に review_for_discussion になる。"""
        cases: list[tuple[str, dict[str, object]]] = [
            (
                "low_prune_confidence_079",
                _make_answers(
                    prot_scores={k: 0.10 for k in screener.PROTECTION_QUESTION_KEYS},
                    category="auto_prune_candidate",
                    cat_confidence=0.79,
                ),
            ),
            (
                "borderline_prot_040",
                _make_answers(
                    prot_scores={"prot_sole_coverage_hint": 0.40},
                    category="auto_prune_candidate",
                    cat_confidence=0.95,
                ),
            ),
            (
                "borderline_prot_064",
                _make_answers(
                    prot_scores={"prot_critical_invariant": 0.64},
                    category="auto_prune_candidate",
                    cat_confidence=0.95,
                ),
            ),
            (
                "low_keep_confidence_074",
                _make_answers(
                    prot_scores={k: 0.30 for k in screener.PROTECTION_QUESTION_KEYS},
                    category="keep_protected",
                    cat_confidence=0.74,
                ),
            ),
            (
                "needs_discussion_high_conf",
                _make_answers(
                    prot_scores={k: 0.05 for k in screener.PROTECTION_QUESTION_KEYS},
                    category="needs_discussion",
                    cat_confidence=0.95,
                ),
            ),
            (
                "other_high_conf",
                _make_answers(
                    prot_scores={k: 0.05 for k in screener.PROTECTION_QUESTION_KEYS},
                    category="other",
                    cat_confidence=0.95,
                ),
            ),
            (
                "missing_one_protection_answer",
                _make_answers(
                    prot_scores={k: 0.05 for k in screener.PROTECTION_QUESTION_KEYS},
                    category="auto_prune_candidate",
                    cat_confidence=0.95,
                    omit_prot={"prot_bug_regression"},
                ),
            ),
        ]

        for label, mock_resp in cases:
            with self.subTest(case=label):
                code, out, err = _run_cli(
                    ["--stdin"],
                    opener=lambda req, timeout=30.0, r=mock_resp: _FakeHTTPResponse(r),
                    env={"GEMINI_API_KEY": "dummy-key"},
                    stdin_text=json.dumps([_make_candidate(cand_id=f"T-{label}")]),
                )
                self.assertEqual(code, 0, err)
                res = json.loads(out)["results"][0]
                self.assertEqual(res["action"], "review_for_discussion")

    def test_P4_06_secret_guard_blocks_before_send_without_exposing_value(self) -> None:
        """P4-06: 秘密鍵ヘッダや主要 API トークン混入時は送信前に終了コード 2 で遮断し実値を出さない。"""
        # 実秘密値をソースに含めないよう文字列連結でダミートークンを組み立てる
        dummy_secrets = [
            ("private_key_code", "code", "-----BEGIN " + "RSA PRIVATE KEY-----\nMIIE..."),
            ("google_aiza_code", "code", 'API_KEY = "' + "AIza" + "A" * 24 + '"'),
            ("github_ghp_git_log", "git_log", "leaked " + "ghp_" + "B" * 24),
            ("github_ghs_spec_refs", "spec_refs", "token=" + "ghs_" + "G" * 24),
            ("github_pat_code", "code", "PAT = '" + "github_pat_" + "C" * 24 + "'"),
            ("openai_sk_code", "code", "OPENAI = '" + "sk-" + "D" * 24 + "'"),
            ("aws_akia_git_log", "git_log", "AWS=" + "AKIA" + "E" * 16),
        ]

        for case_name, field_name, secret_text in dummy_secrets:
            with self.subTest(case=case_name):
                cand = _make_candidate(cand_id="T-SEC-01")
                cand[field_name] = secret_text
                called = False

                def fail_if_called(req: object, timeout: float = 30.0) -> _FakeHTTPResponse:
                    nonlocal called
                    called = True
                    raise AssertionError("秘密情報混入時に API が呼ばれてはいけません。")

                code, out, err = _run_cli(
                    ["--stdin"],
                    opener=fail_if_called,
                    env={},
                    stdin_text=json.dumps([cand]),
                )
                self.assertEqual(code, 2)
                self.assertFalse(called)
                self.assertEqual(out, "")
                self.assertNotIn(secret_text, err)
                self.assertNotIn(secret_text, out)
                err_json = json.loads(err)
                self.assertEqual(err_json["code"], "secret_detected")

                # --dry-run 時も秘密情報遮断を優先して終了コード 2 にする
                code_dry, out_dry, err_dry = _run_cli(
                    ["--stdin", "--dry-run"],
                    env={},
                    stdin_text=json.dumps([cand]),
                )
                self.assertEqual(code_dry, 2)
                self.assertEqual(out_dry, "")
                self.assertNotIn(secret_text, err_dry)

    def test_P4_07_missing_api_key_secret_masking_and_safety_block(self) -> None:
        """P4-07: キー未設定時の終了コード 2、エラー時の API キーマスク、安全遮断時の終了コード 3 を検証する。"""
        payload_stdin = json.dumps([_make_candidate(cand_id="T-ERR-01")])

        code_no_key, _, err_no_key = _run_cli(["--stdin"], env={}, stdin_text=payload_stdin)
        self.assertEqual(code_no_key, 2)
        self.assertEqual(json.loads(err_no_key)["code"], "missing_api_key")

        # HTTP エラーに API キー実値が混入しても出力でマスクされる
        secret_api_key = "AIza" + "Z" * 24

        def error_echo_opener(req: object, timeout: float = 30.0) -> _FakeHTTPResponse:
            err_body = {"error": {"code": "internal", "message": f"failed for key={secret_api_key}"}}
            raise urllib.error.HTTPError(
                url=run_decisions.DEFAULT_ENDPOINT,
                code=500,
                msg="Internal Error",
                hdrs={},  # type: ignore[arg-type]
                fp=io.BytesIO(json.dumps(err_body).encode("utf-8")),
            )

        code_err, out_err, stderr_err = _run_cli(
            ["--stdin", "--format", "table"],
            opener=error_echo_opener,
            env={"GEMINI_API_KEY": secret_api_key},
            stdin_text=payload_stdin,
        )
        self.assertEqual(code_err, 1)
        self.assertEqual(out_err, "")
        self.assertNotIn(secret_api_key, stderr_err)
        self.assertIn("[REDACTED]", stderr_err)

        # HTTP 200 prompt_feedback 遮断 -> 終了コード 3
        blocked_200 = {
            "answers": {},
            "prompt_feedback": {
                "block_reason": "safety",
                "block_reason_message": "Blocked by safety filter.",
            },
        }
        code_blk200, _, err_blk200 = _run_cli(
            ["--stdin"],
            opener=lambda req, timeout=30.0: _FakeHTTPResponse(blocked_200),
            env={"GEMINI_API_KEY": "dummy-key"},
            stdin_text=payload_stdin,
        )
        self.assertEqual(code_blk200, 3)
        self.assertEqual(json.loads(err_blk200)["code"], "safety_blocked")

        # HTTP 400 safety 遮断 -> 終了コード 3
        def http_400_safety_opener(req: object, timeout: float = 30.0) -> _FakeHTTPResponse:
            err_body = {"error": {"code": "safety", "message": "Safety violation"}}
            raise urllib.error.HTTPError(
                url=run_decisions.DEFAULT_ENDPOINT,
                code=400,
                msg="Bad Request",
                hdrs={},  # type: ignore[arg-type]
                fp=io.BytesIO(json.dumps(err_body).encode("utf-8")),
            )

        code_blk400, _, err_blk400 = _run_cli(
            ["--stdin"],
            opener=http_400_safety_opener,
            env={"GEMINI_API_KEY": "dummy-key"},
            stdin_text=payload_stdin,
        )
        self.assertEqual(code_blk400, 3)
        self.assertEqual(json.loads(err_blk400)["code"], "safety_blocked")

    def test_P4_08_parallel_max_workers_preserves_input_order(self) -> None:
        """P4-08: --max-workers 2 の並列実行で完了順が逆転しても出力順序は入力順を保持する。"""
        candidates = [
            _make_candidate(cand_id="T-01", test_name="test_first"),
            _make_candidate(cand_id="T-02", test_name="test_second"),
            _make_candidate(cand_id="T-03", test_name="test_third"),
        ]
        second_finished = threading.Event()
        completion_order: list[str] = []
        order_lock = threading.Lock()

        def concurrent_opener(req: urllib.request.Request, timeout: float = 30.0) -> _FakeHTTPResponse:
            payload = json.loads(req.data.decode("utf-8"))  # type: ignore[union-attr]
            meta_text = payload["input"][0]["text"]
            if "Test ID: T-01\n" in meta_text:
                # T-02 が別ワーカーで完了するまで待機し、実際の並列実行と完了順逆転を確定させる
                waited = second_finished.wait(timeout=2.0)
                if not waited:
                    raise TimeoutError("T-02 did not run concurrently within timeout")
                with order_lock:
                    completion_order.append("T-01")
                return _FakeHTTPResponse(
                    _make_answers(prot_scores={"prot_spec_linked": 0.85}, category="keep_protected", cat_confidence=0.90)
                )
            if "Test ID: T-02\n" in meta_text:
                with order_lock:
                    completion_order.append("T-02")
                second_finished.set()
                return _FakeHTTPResponse(
                    _make_answers(category="auto_prune_candidate", cat_confidence=0.92)
                )
            if "Test ID: T-03\n" in meta_text:
                with order_lock:
                    completion_order.append("T-03")
                return _FakeHTTPResponse(
                    _make_answers(category="needs_discussion", cat_confidence=0.88)
                )
            raise AssertionError(f"Unexpected meta_text: {meta_text!r}")

        code, out, err = _run_cli(
            ["--stdin", "--max-workers", "2"],
            opener=concurrent_opener,
            env={"GEMINI_API_KEY": "dummy-key"},
            stdin_text=json.dumps(candidates),
        )
        self.assertEqual(code, 0, err)
        self.assertEqual(completion_order.index("T-02"), 0)
        self.assertGreater(completion_order.index("T-01"), 0)

        data = json.loads(out)
        self.assertEqual([row["id"] for row in data["results"]], ["T-01", "T-02", "T-03"])
        self.assertEqual(
            [row["action"] for row in data["results"]],
            ["skip_keep", "verify_for_prune", "review_for_discussion"],
        )
        self.assertEqual(
            data["summary"],
            {"skip_keep": 1, "verify_for_prune": 1, "review_for_discussion": 1},
        )
        self.assertEqual(data["usage"]["total_input_tokens"], 360)
        self.assertEqual(data["usage"]["total_output_tokens"], 0)

    def test_P4_09_format_table_and_empty_input(self) -> None:
        """P4-09: --format table で Markdown 表を出力でき、空配列 [] は API 非呼び出しで終了コード 0。"""
        candidates = [
            _make_candidate(cand_id="T-TBL-1", test_name="test_権限チェック|認可"),
            _make_candidate(cand_id="T-TBL-2", test_name="test_空実装"),
        ]

        def table_opener(req: urllib.request.Request, timeout: float = 30.0) -> _FakeHTTPResponse:
            payload = json.loads(req.data.decode("utf-8"))  # type: ignore[union-attr]
            meta_text = payload["input"][0]["text"]
            if "Test ID: T-TBL-1\n" in meta_text:
                return _FakeHTTPResponse(
                    _make_answers(
                        prot_scores={"prot_critical_invariant": 0.91},
                        category="keep_protected",
                        cat_confidence=0.93,
                        input_tokens=100,
                    )
                )
            if "Test ID: T-TBL-2\n" in meta_text:
                return _FakeHTTPResponse(
                    _make_answers(
                        category="auto_prune_candidate",
                        cat_confidence=0.89,
                        input_tokens=80,
                    )
                )
            raise AssertionError(f"Unexpected meta_text: {meta_text!r}")

        code, out, err = _run_cli(
            ["--stdin", "--format", "table"],
            opener=table_opener,
            env={"GEMINI_API_KEY": "dummy-key"},
            stdin_text=json.dumps(candidates, ensure_ascii=False),
        )
        self.assertEqual(code, 0, err)
        self.assertIn("| id | action | category | confidence | max_prot | triggered | location | test_name |", out)
        self.assertIn("T-TBL-1", out)
        self.assertIn("skip_keep", out)
        self.assertIn("verify_for_prune", out)
        self.assertIn("test_権限チェック\\|認可", out)
        self.assertIn("Summary: total=2, skip_keep=1, verify_for_prune=1, review_for_discussion=0", out)
        self.assertIn("usage: input_tokens=180, output_tokens=0", out)

        # 空配列 [] はキー未設定・API 非呼び出しで終了コード 0
        code_empty, out_empty, err_empty = _run_cli(
            ["--stdin"],
            opener=lambda req, timeout=30.0: (_ for _ in ()).throw(AssertionError("called")),
            env={},
            stdin_text="[]",
        )
        self.assertEqual(code_empty, 0, err_empty)
        self.assertEqual(json.loads(out_empty)["status"], "skipped_empty_input")

    def test_P4_10_invalid_inputs_and_flags_return_exit_code_2(self) -> None:
        """P4-10: 不正 JSON・スキーマ違反・不正フラグ時は API を呼ばず終了コード 2 を返す。"""
        bad_inputs = [
            "{not json",
            '{"id": "not-a-list"}',
            json.dumps([{"id": "T-1", "file": "a.py", "line": 1, "code": "pass"}]),
            json.dumps([{"id": "T-1", "file": "a.py", "line": -1, "test_name": "t", "code": "pass"}]),
            json.dumps([{"id": "T-1", "file": "a.py", "line": True, "test_name": "t", "code": "pass"}]),
        ]
        for raw in bad_inputs:
            with self.subTest(raw=raw):
                code, out, err = _run_cli(["--stdin"], env={}, stdin_text=raw)
                self.assertEqual(code, 2)
                self.assertEqual(out, "")
                self.assertEqual(json.loads(err)["exit_code"], 2)

        code_workers, _, err_workers = _run_cli(
            ["--stdin", "--max-workers", "0"], env={}, stdin_text="[]"
        )
        self.assertEqual(code_workers, 2)
        self.assertEqual(json.loads(err_workers)["code"], "invalid_max_workers")

        with tempfile.TemporaryDirectory() as tmp:
            missing_file = Path(tmp) / "missing.json"
            code_missing, _, err_missing = _run_cli(["--input", str(missing_file)], env={})
            self.assertEqual(code_missing, 2)
            self.assertEqual(json.loads(err_missing)["code"], "input_read_error")

    def test_P4_11_sk_boundary_and_multiline_pem_masking(self) -> None:
        """P4-11: task-executor-... や flask-... を誤検知せず、複数行 PEM ブロック・単独ヘッダ・URL エンコード値をマスクする。"""
        cand = _make_candidate(
            cand_id="T-SAFE-SK",
            test_name="test_task-executor-worker-pool-config",
            code='def test_task_executor():\n    cfg = "flask-app-secret-config-1234567890"\n    svc = "task-executor-worker-pool-config"\n',
        )
        code, out, err = _run_cli(
            ["--stdin", "--dry-run"],
            env={},
            stdin_text=json.dumps([cand]),
        )
        self.assertEqual(code, 0, msg=err)
        self.assertEqual(json.loads(out)["total"], 1)

        pem_block = (
            "-----BEGIN "
            + "RSA PRIVATE KEY-----\n"
            + "MIIEpAIBAAKCAQEAKeyBodyLine999\n"
            + "-----END "
            + "RSA PRIVATE KEY-----"
        )
        raw_secret = "key+with/secret=chars&456"
        encoded_secret = urllib.parse.quote(raw_secret, safe="")
        masked = screener.mask_secret(
            f"err key={encoded_secret}\n{pem_block}\n-----BEGIN " + "PRIVATE KEY-----\npartial",
            raw_secret,
        )
        self.assertNotIn(encoded_secret, masked)
        self.assertNotIn("MIIEpAIBAAKCAQEAKeyBodyLine999", masked)
        self.assertNotIn("-----BEGIN ", masked)
        self.assertIn("[REDACTED]", masked)

    def test_P4_12_input_env_block_and_invalid_encoding_classification(self) -> None:
        """P4-12: --input .env 系を secret_env_file (exit 2) で遮断し雛形を許容、非 UTF-8 入力を invalid_input_encoding (exit 2) に分類する。"""
        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            env_file = tmp_dir / ".env"
            env_file.write_text("[]", encoding="utf-8")
            env_local = tmp_dir / ".env.local"
            env_local.write_text("[]", encoding="utf-8")
            env_example = tmp_dir / ".env.local.example"
            env_example.write_text(json.dumps([_make_candidate()], ensure_ascii=False), encoding="utf-8")
            bad_utf8 = tmp_dir / "bad_cp932.json"
            bad_utf8.write_bytes(b"\x82\xa0\xff\xfe")

            for blocked in (env_file, env_local):
                with self.subTest(blocked=blocked.name):
                    code, out, err = _run_cli(["--input", str(blocked), "--dry-run"], env={})
                    self.assertEqual(code, 2)
                    self.assertEqual(out, "")
                    err_obj = json.loads(err)
                    self.assertEqual(err_obj["code"], "secret_env_file")
                    self.assertEqual(err_obj["exit_code"], 2)

            code_ex, out_ex, err_ex = _run_cli(["--input", str(env_example), "--dry-run"], env={})
            self.assertEqual(code_ex, 0, msg=err_ex)
            self.assertEqual(json.loads(out_ex)["total"], 1)

            # Promoted Fix 1b: UnicodeDecodeError -> invalid_input_encoding (exit 2, not api_request_failed / exit 1)
            code_enc, out_enc, err_enc = _run_cli(["--input", str(bad_utf8), "--dry-run"], env={})
            self.assertEqual(code_enc, 2)
            self.assertEqual(out_enc, "")
            err_enc_obj = json.loads(err_enc)
            self.assertEqual(err_enc_obj["code"], "invalid_input_encoding")
            self.assertEqual(err_enc_obj["exit_code"], 2)

    def test_P4_13_cp932_subprocess_outputs_japanese_utf8(self) -> None:
        """P4-13: PYTHONIOENCODING=cp932 下でも日本語と cp932 非対応文字を含む --dry-run が成功する。"""
        candidates = [
            _make_candidate(
                cand_id="T-CP932-01",
                test_name="test_日本語と絵文字_\U0001f680",
                code="def test_jp():\n    assert '日本語 \U0001f680'\n",
            )
        ]
        with tempfile.TemporaryDirectory() as tmp:
            input_path = Path(tmp) / "candidates.json"
            input_path.write_text(json.dumps(candidates, ensure_ascii=False), encoding="utf-8")

            script_path = _SCRIPT_DIR / "screen_tests_decision1.py"
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
            self.assertIn("\U0001f680", parsed["items"][0]["test_name"])


if __name__ == "__main__":
    unittest.main()
