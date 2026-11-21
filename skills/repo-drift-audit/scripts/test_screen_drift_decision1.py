#!/usr/bin/env python3
"""screen_drift_decision1.py のオフライン単体テスト。

外部通信を行わず、モック opener 注入と一時ディレクトリ（非 Git および Git）を用いて
docs / backlog / candidates の 3 モード、決定論的ヒント、安全側分類、秘密情報遮断、
上限ガード、安全フィルタ遮断（HTTP 400 / HTTP 200）、並列順序保持を検証する。
"""

from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error

_SCRIPT_DIR = Path(__file__).resolve().parent
if str(_SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPT_DIR))

_DECISIONS_DIR = Path(__file__).resolve().parents[2] / "gemini-decisions-api" / "scripts"
if str(_DECISIONS_DIR) not in sys.path:
    sys.path.insert(0, str(_DECISIONS_DIR))

import run_decisions  # noqa: E402
import screen_drift_decision1 as sdd  # noqa: E402

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
        code = sdd.main(
            argv,
            opener=opener,  # type: ignore[arg-type]
            env=env if env is not None else {},
            stdin_text=stdin_text,
        )
    return code, stdout_buf.getvalue(), stderr_buf.getvalue()


def _make_docs_response(
    *,
    stale: float = 0.10,
    broken: float = 0.10,
    mech: float = 0.20,
    discuss: float = 0.15,
    severity_score: float = 0.20,
    action: str = "likely_clean",
    action_conf: float = 0.92,
    input_tokens: int = 200,
) -> dict[str, object]:
    return {
        "answers": {
            "stale_status_or_facts": {
                "type": "noul",
                "noul": stale,
                "confidence": round(max(stale, 1.0 - stale), 4),
            },
            "broken_or_obsolete_refs": {
                "type": "noul",
                "noul": broken,
                "confidence": round(max(broken, 1.0 - broken), 4),
            },
            "mechanizable_workflow": {
                "type": "noul",
                "noul": mech,
                "confidence": round(max(mech, 1.0 - mech), 4),
            },
            "needs_discussion": {
                "type": "noul",
                "noul": discuss,
                "confidence": round(max(discuss, 1.0 - discuss), 4),
            },
            "drift_severity": {
                "type": "score",
                "score": severity_score,
                "legend": {str(i): label for i, label in enumerate(sdd.DRIFT_SEVERITY_CRITERIA)},
                "probabilities": {"0": 0.85, "1": 0.10, "2": 0.04, "3": 0.01},
                "confidence": 0.85,
            },
            "recommended_action": {
                "type": "choice",
                "choice": action,
                "probabilities": {action: action_conf, "other": round(1.0 - action_conf, 4)},
                "confidence": action_conf,
            },
        },
        "usage": {
            "total_input_tokens": input_tokens,
            "total_output_tokens": 0,
            "total_tokens": input_tokens,
        },
    }


def _make_candidate_response(
    *,
    fits: float = 0.90,
    discuss: float = 0.15,
    mech: float = 0.25,
    impact_score: float = 1.5,
    route: str = "plan_worker_autonomous",
    route_conf: float = 0.91,
    input_tokens: int = 140,
) -> dict[str, object]:
    return {
        "answers": {
            "fits_single_track": {
                "type": "noul",
                "noul": fits,
                "confidence": round(max(fits, 1.0 - fits), 4),
            },
            "needs_discussion": {
                "type": "noul",
                "noul": discuss,
                "confidence": round(max(discuss, 1.0 - discuss), 4),
            },
            "deterministic_mechanizable": {
                "type": "noul",
                "noul": mech,
                "confidence": round(max(mech, 1.0 - mech), 4),
            },
            "impact_severity": {
                "type": "score",
                "score": impact_score,
                "legend": {str(i): label for i, label in enumerate(sdd.CANDIDATES_IMPACT_CRITERIA)},
                "probabilities": {"0": 0.05, "1": 0.45, "2": 0.45, "3": 0.05},
                "confidence": 0.45,
            },
            "dispatch_route": {
                "type": "choice",
                "choice": route,
                "probabilities": {route: route_conf, "other": round(1.0 - route_conf, 4)},
                "confidence": route_conf,
            },
        },
        "usage": {
            "total_input_tokens": input_tokens,
            "total_output_tokens": 0,
            "total_tokens": input_tokens,
        },
    }


def _create_sample_repo(base: Path) -> Path:
    (base / "docs").mkdir(parents=True, exist_ok=True)
    (base / "src").mkdir(parents=True, exist_ok=True)
    (base / "src" / "main.py").write_text("def run():\n    return 1\n", encoding="utf-8")
    (base / "README.md").write_text(
        "# Sample\n\nSee [main](src/main.py) and `src/main.py`.\n",
        encoding="utf-8",
    )
    (base / "docs" / "clean.md").write_text(
        "# Clean Guide\n\nUses `src/main.py`.\n",
        encoding="utf-8",
    )
    (base / "docs" / "broken.md").write_text(
        "# Broken Guide\n\n"
        "See [deleted](src/deleted.py) and `src/missing.py`.\n"
        "Ignore example `foo/bar.txt`, `https://example.com/a/b`, `docs/*.md`, `skills/<name>/SKILL.md`.\n"
        "```\nSee `src/in_code_block.py` and [x](docs/nope.md)\n```\n",
        encoding="utf-8",
    )
    return base


class QuestionSchemaDesignTests(unittest.TestCase):
    def test_questions_pass_validation_and_avoid_negative_noul_phrasing(self) -> None:
        for name, q_map in (
            ("docs", sdd.build_docs_questions()),
            ("candidates", sdd.build_candidates_questions()),
        ):
            payload = {
                "model": sdd.DEFAULT_MODEL,
                "input": [{"type": "text", "text": "sample"}],
                "questions": q_map,
            }
            self.assertEqual(run_decisions.validate_payload(payload), [], msg=name)
            for key, body in q_map.items():
                if body["type"] == "noul":
                    inst = body["instructions"]
                    for pat in NEGATIVE_PHRASING_PATTERNS:
                        self.assertIsNone(
                            pat.search(inst),
                            msg=f"{name}.{key} contains negative phrasing: {inst}",
                        )
                if body["type"] == "choice":
                    self.assertIn("other", body["criteria"], msg=f"{name}.{key} missing 'other'")


class DocsModeTests(unittest.TestCase):
    def test_missing_path_hints_deterministic_filtering(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = _create_sample_repo(Path(tmp))
            ctx = sdd.collect_repo_context(root, 10)
            self.assertFalse(ctx.is_git)
            broken_text = (root / "docs" / "broken.md").read_text(encoding="utf-8")
            hints = sdd.extract_missing_path_hints(broken_text, "docs/broken.md", ctx)
            self.assertEqual(hints, ["src/deleted.py", "src/missing.py"])

    def test_docs_dry_run_and_table_non_git_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = _create_sample_repo(Path(tmp))
            code, out, err = _run_cli(
                ["docs", "--repo", str(root), "--dry-run", "--format", "json"],
            )
            self.assertEqual(code, 0, msg=err)
            report = json.loads(out)
            self.assertEqual(report["status"], "dry_run")
            self.assertFalse(report["is_git"])
            self.assertEqual(report["total"], 3)
            files = [item["file"] for item in report["items"]]
            self.assertEqual(files, ["README.md", "docs/broken.md", "docs/clean.md"])

            code_t, out_t, err_t = _run_cli(
                ["docs", "--repo", str(root), "--dry-run", "--format", "table"],
            )
            self.assertEqual(code_t, 0, msg=err_t)
            self.assertIn("docs/broken.md", out_t)
            self.assertIn("Summary: dry_run subcommand=docs total=3", out_t)

    def test_docs_safe_side_classification_and_parallel_order(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = _create_sample_repo(Path(tmp))
            (root / "docs" / "mech.md").write_text(
                "# Mechanical Steps\n\nFollow deterministic rules.\n",
                encoding="utf-8",
            )
            lock = threading.Lock()
            seen_docs: list[str] = []

            def mock_opener(req: object, timeout: float = 30.0) -> _FakeHTTPResponse:
                body = json.loads(req.data.decode("utf-8"))  # type: ignore[attr-defined]
                doc_text = body["input"][1]["text"]
                if "Document Path: docs/clean.md" in doc_text:
                    # 意図的に遅延させて並列完了順をずらす
                    time.sleep(0.05)
                    resp = _make_docs_response(action="likely_clean", action_conf=0.95)
                elif "Document Path: docs/broken.md" in doc_text:
                    # モデルが likely_clean を返しても missing_path_hints で安全側へ倒れること
                    resp = _make_docs_response(action="likely_clean", action_conf=0.99)
                elif "Document Path: docs/mech.md" in doc_text:
                    resp = _make_docs_response(
                        stale=0.10,
                        broken=0.10,
                        mech=0.82,
                        action="mechanization_review",
                        action_conf=0.88,
                    )
                else:
                    resp = _make_docs_response(action="likely_clean", action_conf=0.91)
                with lock:
                    seen_docs.append(doc_text.splitlines()[0])
                return _FakeHTTPResponse(resp)

            code, out, err = _run_cli(
                [
                    "docs",
                    "--repo",
                    str(root),
                    "--max-workers",
                    "4",
                    "--format",
                    "json",
                ],
                opener=mock_opener,
                env={"GEMINI_API_KEY": "test-dummy-key"},
            )
            self.assertEqual(code, 0, msg=err)
            report = json.loads(out)
            self.assertEqual(len(seen_docs), 4)
            self.assertEqual(
                [r["file"] for r in report["results"]],
                ["README.md", "docs/broken.md", "docs/clean.md", "docs/mech.md"],
            )
            by_file = {r["file"]: r for r in report["results"]}
            self.assertEqual(by_file["README.md"]["bucket"], "low_priority_clean")
            self.assertEqual(by_file["docs/clean.md"]["bucket"], "low_priority_clean")
            self.assertEqual(by_file["docs/broken.md"]["bucket"], "prioritize_for_audit")
            self.assertIn("missing_path_hints(2)", by_file["docs/broken.md"]["reasons"])
            self.assertEqual(by_file["docs/mech.md"]["bucket"], "mechanization_candidate")
            self.assertEqual(report["usage"]["total_output_tokens"], 0)
            self.assertIn("ゼロ乖離の保証ではありません", report["note"])

    def test_docs_git_repo_collects_log_and_staleness(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = _create_sample_repo(Path(tmp))
            try:
                subprocess.run(["git", "init"], cwd=root, check=True, capture_output=True)
                subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=root, check=True, capture_output=True)
                subprocess.run(["git", "config", "user.name", "Tester"], cwd=root, check=True, capture_output=True)
                subprocess.run(["git", "add", "."], cwd=root, check=True, capture_output=True)
                subprocess.run(["git", "commit", "-m", "initial"], cwd=root, check=True, capture_output=True)
            except (OSError, subprocess.CalledProcessError) as exc:
                self.skipTest(f"git unavailable for test: {exc}")

            code, out, err = _run_cli(
                ["docs", "--repo", str(root), "--paths", "README.md", "--dry-run"],
            )
            self.assertEqual(code, 0, msg=err)
            report = json.loads(out)
            self.assertTrue(report["is_git"])
            self.assertEqual(report["total"], 1)
            self.assertEqual(report["items"][0]["staleness_days"], 0)
            snapshot = report["items"][0]["payload"]["input"][0]["text"]
            self.assertIn("Recent Git Log:", snapshot)
            self.assertIn("initial", snapshot)


class BacklogModeTests(unittest.TestCase):
    def test_backlog_markdown_extraction_and_single_request_call(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = _create_sample_repo(Path(tmp))
            backlog_file = root / "BACKLOG.md"
            backlog_file.write_text(
                "# Backlog\n\n"
                "- [x] Already checked item\n"
                "- [ ] Remove deprecated worker script\n"
                "```\n- [ ] Task inside code fence must be ignored\n```\n"
                "- [ ] Add validation test for main.py\n",
                encoding="utf-8",
            )

            captured_payloads: list[dict[str, object]] = []

            def mock_opener(req: object, timeout: float = 30.0) -> _FakeHTTPResponse:
                body = json.loads(req.data.decode("utf-8"))  # type: ignore[attr-defined]
                captured_payloads.append(body)
                return _FakeHTTPResponse(
                    {
                        "answers": {
                            "item_0001": {
                                "type": "choice",
                                "choice": "likely_resolved",
                                "confidence": 0.91,
                            },
                            "item_0002": {
                                "type": "choice",
                                "choice": "still_open",
                                "confidence": 0.88,
                            },
                        },
                        "usage": {"total_input_tokens": 300, "total_output_tokens": 0, "total_tokens": 300},
                    }
                )

            code, out, err = _run_cli(
                ["backlog", "--backlog", str(backlog_file), "--repo", str(root), "--format", "json"],
                opener=mock_opener,
                env={"GEMINI_API_KEY": "test-dummy-key"},
            )
            self.assertEqual(code, 0, msg=err)
            self.assertEqual(len(captured_payloads), 1)
            self.assertEqual(list(captured_payloads[0]["questions"].keys()), ["item_0001", "item_0002"])  # type: ignore[union-attr]

            report = json.loads(out)
            self.assertEqual(report["total"], 2)
            self.assertEqual(report["results"][0]["line"], 4)
            self.assertTrue(report["results"][0]["needs_verification"])
            self.assertEqual(report["results"][1]["line"], 8)
            self.assertFalse(report["results"][1]["needs_verification"])

    def test_backlog_json_input_and_empty_skip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = _create_sample_repo(Path(tmp))
            empty_md = root / "EMPTY.md"
            empty_md.write_text("- [x] Done only\n", encoding="utf-8")
            code_e, out_e, err_e = _run_cli(
                ["backlog", "--backlog", str(empty_md), "--repo", str(root)],
                env={},
            )
            self.assertEqual(code_e, 0, msg=err_e)
            self.assertEqual(json.loads(out_e)["status"], "skipped_empty_input")

            json_backlog = root / "items.json"
            json_backlog.write_text(
                json.dumps(
                    [{"id": "BL-1", "file": "docs/todo.md", "line": 12, "text": "Update CLI docs"}],
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )
            code_d, out_d, err_d = _run_cli(
                ["backlog", "--backlog", str(json_backlog), "--repo", str(root), "--dry-run", "--format", "table"],
            )
            self.assertEqual(code_d, 0, msg=err_d)
            self.assertIn("BL-1", out_d)

    def test_backlog_exceeds_1000_questions_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = _create_sample_repo(Path(tmp))
            big_md = root / "BIG.md"
            lines = [f"- [ ] Task item number {i}" for i in range(1001)]
            big_md.write_text("\n".join(lines), encoding="utf-8")
            code, _, err = _run_cli(
                ["backlog", "--backlog", str(big_md), "--repo", str(root), "--dry-run"],
            )
            self.assertEqual(code, 2)
            self.assertIn("question_limit_exceeded", err)


class CandidatesModeTests(unittest.TestCase):
    def test_input_and_stdin_mutual_exclusion(self) -> None:
        code_none, _, err_none = _run_cli(["candidates"])
        self.assertEqual(code_none, 2)
        self.assertIn("invalid_input_source", err_none)

        code_both, _, err_both = _run_cli(["candidates", "--input", "a.json", "--stdin"], stdin_text="[]")
        self.assertEqual(code_both, 2)
        self.assertIn("invalid_input_source", err_both)

    def test_empty_candidates_skipped_without_api_key(self) -> None:
        code, out, err = _run_cli(["candidates", "--stdin"], stdin_text="[]")
        self.assertEqual(code, 0, msg=err)
        self.assertEqual(json.loads(out)["status"], "skipped_empty_input")

    def test_candidates_parallel_order_and_parent_review_escalation(self) -> None:
        items = [
            {
                "id": "C-1",
                "category": "doc_drift",
                "title": "Fix broken path in README",
                "files": ["README.md"],
                "evidence": "README.md:10 mentions missing.py",
                "symptom": "Broken link",
            },
            {
                "id": "C-2",
                "category": "structure",
                "title": "Split oversized module",
                "files": "src/big.py",
                "evidence": "src/big.py is 900 lines",
                "symptom": "Needs design choice on split boundary",
            },
            {
                "id": "C-3",
                "category": "skill_drift",
                "title": "Uncertain item",
                "evidence": "Ambiguous wording",
                "symptom": "Low confidence route",
            },
        ]

        def mock_opener(req: object, timeout: float = 30.0) -> _FakeHTTPResponse:
            body = json.loads(req.data.decode("utf-8"))  # type: ignore[attr-defined]
            text = body["input"][0]["text"]
            if "Candidate ID: C-1" in text:
                time.sleep(0.05)
                return _FakeHTTPResponse(
                    _make_candidate_response(discuss=0.10, route="plan_worker_autonomous", route_conf=0.92)
                )
            if "Candidate ID: C-2" in text:
                return _FakeHTTPResponse(
                    _make_candidate_response(discuss=0.65, route="plan_worker_discussion", route_conf=0.88)
                )
            return _FakeHTTPResponse(
                _make_candidate_response(discuss=0.20, route="plan_worker_autonomous", route_conf=0.55)
            )

        code, out, err = _run_cli(
            ["candidates", "--stdin", "--max-workers", "3", "--format", "json"],
            opener=mock_opener,
            env={"GEMINI_API_KEY": "test-dummy-key"},
            stdin_text=json.dumps(items, ensure_ascii=False),
        )
        self.assertEqual(code, 0, msg=err)
        report = json.loads(out)
        self.assertEqual([r["id"] for r in report["results"]], ["C-1", "C-2", "C-3"])
        by_id = {r["id"]: r for r in report["results"]}
        self.assertFalse(by_id["C-1"]["needs_parent_review"])
        self.assertTrue(by_id["C-2"]["needs_parent_review"])
        self.assertIn("needs_discussion>=0.50", by_id["C-2"]["reasons"])
        self.assertTrue(by_id["C-3"]["needs_parent_review"])
        self.assertIn("low_confidence<0.80", by_id["C-3"]["reasons"])


class SecurityAndErrorHandlingTests(unittest.TestCase):
    def test_env_blocked_and_env_example_allowed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = _create_sample_repo(Path(tmp))
            (root / ".env").write_text("SECRET_VAL=12345\n", encoding="utf-8")
            (root / ".env.example").write_text("SECRET_VAL=placeholder\n", encoding="utf-8")

            code_block, _, err_block = _run_cli(
                ["docs", "--repo", str(root), "--paths", ".env", "--dry-run"],
            )
            self.assertEqual(code_block, 2)
            self.assertIn("secret_env_file", err_block)

            code_ok, out_ok, err_ok = _run_cli(
                ["docs", "--repo", str(root), "--paths", ".env.example", "--dry-run"],
            )
            self.assertEqual(code_ok, 0, msg=err_ok)
            self.assertEqual(json.loads(out_ok)["total"], 1)

    def test_secret_patterns_blocked_and_masked_before_api_call(self) -> None:
        secrets = [
            "-----BEGIN RSA PRIVATE KEY-----\nABC",
            "AIzaSyDummyGoogleApiKey1234567890",
            "ghp_DummyGitHubTokenValue1234567890",
            "github_pat_DummyFineGrainedToken123456",
            "sk-DummySecretKeyValue1234567890",
            "AKIAIOSFODNN7EXAMPLE",
        ]
        for secret in secrets:
            payload = [
                {
                    "id": "C-SEC",
                    "category": "doc_drift",
                    "title": "Secret test",
                    "evidence": f"token={secret}",
                    "symptom": "Contains leaked credential",
                }
            ]
            called = False

            def fail_if_called(req: object, timeout: float = 30.0) -> _FakeHTTPResponse:
                nonlocal called
                called = True
                return _FakeHTTPResponse({})

            code, _, err = _run_cli(
                ["candidates", "--stdin"],
                opener=fail_if_called,
                env={"GEMINI_API_KEY": "MY_ACTUAL_GEMINI_KEY"},
                stdin_text=json.dumps(payload),
            )
            self.assertEqual(code, 2, msg=f"failed for {secret}: {err}")
            self.assertFalse(called)
            self.assertIn("secret_detected", err)
            self.assertNotIn(secret, err)

    def test_max_chars_limit_and_missing_api_key_and_key_masking(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = _create_sample_repo(Path(tmp))
            code_max, _, err_max = _run_cli(
                ["docs", "--repo", str(root), "--paths", "README.md", "--max-chars", "10", "--dry-run"],
            )
            self.assertEqual(code_max, 2)
            self.assertIn("input_size_limit_exceeded", err_max)

            code_key, _, err_key = _run_cli(
                ["docs", "--repo", str(root), "--paths", "README.md"],
                env={},
            )
            self.assertEqual(code_key, 2)
            self.assertIn("missing_api_key", err_key)

            secret_key = "SUPER_SECRET_GEMINI_KEY_VALUE"

            def error_opener(req: object, timeout: float = 30.0) -> _FakeHTTPResponse:
                raise run_decisions.ApiRequestError(500, f"failed with key={secret_key}")

            code_err, _, err_mask = _run_cli(
                ["docs", "--repo", str(root), "--paths", "README.md"],
                opener=error_opener,
                env={"GEMINI_API_KEY": secret_key},
            )
            self.assertEqual(code_err, 1)
            self.assertNotIn(secret_key, err_mask)
            self.assertIn("[REDACTED]", err_mask)

    def test_safety_blocks_return_exit_code_3(self) -> None:
        cand_json = json.dumps(
            [
                {
                    "id": "C-1",
                    "category": "doc_drift",
                    "title": "Check safety",
                    "evidence": "ev",
                    "symptom": "sym",
                }
            ]
        )

        def http400_opener(req: object, timeout: float = 30.0) -> _FakeHTTPResponse:
            err_body = json.dumps({"error": {"code": "safety", "message": "blocked"}}).encode("utf-8")
            raise urllib.error.HTTPError(
                sdd.DEFAULT_ENDPOINT,
                400,
                "Bad Request",
                None,  # type: ignore[arg-type]
                io.BytesIO(err_body),
            )

        code_400, _, err_400 = _run_cli(
            ["candidates", "--stdin"],
            opener=http400_opener,
            env={"GEMINI_API_KEY": "k"},
            stdin_text=cand_json,
        )
        self.assertEqual(code_400, 3)
        self.assertIn("safety_blocked", err_400)

        def http200_feedback_opener(req: object, timeout: float = 30.0) -> _FakeHTTPResponse:
            return _FakeHTTPResponse(
                {
                    "prompt_feedback": {
                        "block_reason": "PROHIBITED_CONTENT",
                        "block_reason_message": "Blocked by policy",
                    },
                    "answers": {},
                }
            )

        code_200, _, err_200 = _run_cli(
            ["candidates", "--stdin"],
            opener=http200_feedback_opener,
            env={"GEMINI_API_KEY": "k"},
            stdin_text=cand_json,
        )
        self.assertEqual(code_200, 3)
        self.assertIn("safety_blocked", err_200)


if __name__ == "__main__":
    unittest.main()
