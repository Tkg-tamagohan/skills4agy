#!/usr/bin/env python3
"""screen_drift_decision1.py のオフライン単体テスト（SDD-01〜SDD-29）。

外部通信を行わず、モック opener 注入と一時ディレクトリ（非 Git および Git）を用いて
docs / backlog / candidates の 3 モード（chunk 既定および single 互換）、決定論的ヒント、
見出しパンくず、表形式バックログ、--backend 切替、安全側分類、秘密情報遮断、
上限ガード、安全フィルタ遮断（HTTP 400 / HTTP 200）、パイプ切断終了を検証する。
"""

from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import errno
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
from unittest import mock
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
    def test_SDD_01_questions_pass_validation_and_avoid_negative_noul_phrasing(self) -> None:
        """SDD-01: docs / candidates 質問マップがスキーマ検証を通過し否定疑問文を含まない。"""
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
    def test_SDD_02_missing_path_hints_deterministic_filtering(self) -> None:
        """SDD-02: 文書内パスの不在ヒント抽出がコードブロックや外部 URL を除外して決まる。"""
        with tempfile.TemporaryDirectory() as tmp:
            root = _create_sample_repo(Path(tmp))
            ctx = sdd.collect_repo_context(root, 10)
            self.assertFalse(ctx.is_git)
            broken_text = (root / "docs" / "broken.md").read_text(encoding="utf-8")
            hints = sdd.extract_missing_path_hints(broken_text, "docs/broken.md", ctx)
            self.assertEqual(hints, ["src/deleted.py", "src/missing.py"])

    def test_SDD_03_docs_dry_run_and_table_non_git_fallback(self) -> None:
        """SDD-03: 非 Git リポジトリでの docs --dry-run が既定 chunk と single 互換の双方で json / table 動作する。"""
        with tempfile.TemporaryDirectory() as tmp:
            root = _create_sample_repo(Path(tmp))
            # 既定 chunk モード
            code_c, out_c, err_c = _run_cli(
                ["docs", "--repo", str(root), "--dry-run", "--format", "json"],
            )
            self.assertEqual(code_c, 0, msg=err_c)
            report_c = json.loads(out_c)
            self.assertEqual(report_c["status"], "dry_run")
            self.assertEqual(report_c["batch_mode"], "chunk")
            self.assertFalse(report_c["is_git"])
            self.assertEqual(report_c["total"], 3)
            self.assertEqual(report_c["chunk_count"], 1)
            self.assertEqual(report_c["chunks"][0]["files"], ["README.md", "docs/broken.md", "docs/clean.md"])

            code_ct, out_ct, err_ct = _run_cli(
                ["docs", "--repo", str(root), "--dry-run", "--format", "table"],
            )
            self.assertEqual(code_ct, 0, msg=err_ct)
            self.assertIn("docs/broken.md", out_ct)
            self.assertIn("Summary: dry_run subcommand=docs total=3, batch_mode=chunk, chunk_count=1", out_ct)

            # single 互換モード
            code, out, err = _run_cli(
                ["docs", "--repo", str(root), "--batch-mode", "single", "--dry-run", "--format", "json"],
            )
            self.assertEqual(code, 0, msg=err)
            report = json.loads(out)
            self.assertEqual(report["status"], "dry_run")
            self.assertFalse(report["is_git"])
            self.assertEqual(report["total"], 3)
            files = [item["file"] for item in report["items"]]
            self.assertEqual(files, ["README.md", "docs/broken.md", "docs/clean.md"])

            code_t, out_t, err_t = _run_cli(
                ["docs", "--repo", str(root), "--batch-mode", "single", "--dry-run", "--format", "table"],
            )
            self.assertEqual(code_t, 0, msg=err_t)
            self.assertIn("docs/broken.md", out_t)
            self.assertIn("Summary: dry_run subcommand=docs total=3", out_t)

    def test_SDD_04_docs_safe_side_classification_and_parallel_order(self) -> None:
        """SDD-04: docs モードの安全側分類と並列実行時の入力順序保持を検証する。"""
        with tempfile.TemporaryDirectory() as tmp:
            root = _create_sample_repo(Path(tmp))
            (root / "docs" / "mech.md").write_text(
                "# Mechanical Steps\n\nFollow deterministic rules.\n",
                encoding="utf-8",
            )
            lock = threading.Lock()
            seen_docs: list[str] = []
            mech_finished = threading.Event()
            completion_order: list[str] = []

            def mock_opener(req: object, timeout: float = 30.0) -> _FakeHTTPResponse:
                body = json.loads(req.data.decode("utf-8"))  # type: ignore[attr-defined]
                doc_text = body["input"][1]["text"]
                if "Document Path: docs/clean.md" in doc_text:
                    # docs/mech.md が別ワーカーで完了するまで待機し、完了順の逆転を確定させる
                    if not mech_finished.wait(timeout=2.0):
                        raise TimeoutError("docs/mech.md did not complete concurrently within timeout")
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
                    header = doc_text.splitlines()[0]
                    seen_docs.append(header)
                    completion_order.append(header)
                if "Document Path: docs/mech.md" in doc_text:
                    mech_finished.set()
                return _FakeHTTPResponse(resp)

            code, out, err = _run_cli(
                [
                    "docs",
                    "--repo",
                    str(root),
                    "--batch-mode",
                    "single",
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
            mech_idx = next(i for i, h in enumerate(completion_order) if "docs/mech.md" in h)
            clean_idx = next(i for i, h in enumerate(completion_order) if "docs/clean.md" in h)
            self.assertLess(mech_idx, clean_idx)
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

    def test_SDD_05_docs_git_repo_collects_log_and_staleness(self) -> None:
        """SDD-05: Git リポジトリ上で直近ログと陳腐化日数を収集する。"""
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
                ["docs", "--repo", str(root), "--paths", "README.md", "--batch-mode", "single", "--dry-run"],
            )
            self.assertEqual(code, 0, msg=err)
            report = json.loads(out)
            self.assertTrue(report["is_git"])
            self.assertEqual(report["total"], 1)
            self.assertEqual(report["items"][0]["staleness_days"], 0)
            snapshot = report["items"][0]["payload"]["input"][0]["text"]
            self.assertIn("Recent Git Log:", snapshot)
            self.assertIn("initial", snapshot)

    def test_SDD_16_expanded_default_globs_catch_aux_and_instruction_docs(self) -> None:
        """SDD-16: 拡張既定グロブが補助文書とルート指示文書を捕捉し CHANGELOG.md と既定 slop-catalog.md を除外する。"""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            rel_files = [
                "README.md",
                "AGENTS.md",
                "GEMINI.md",
                "CLAUDE.md",
                "CHANGELOG.md",
                "docs/guide.md",
                "skills/demo/SKILL.md",
                "skills/demo/guidelines.md",
                "skills/demo/references/api-reference.md",
                "skills/japanese-tech-writing/references/slop-catalog.md",
                ".agents/skills/helper/notes.md",
                ".agents/rules/r1.md",
                ".agent/rules/r2.md",
                "_agents/rules/sub/r3.md",
                "_agent/rules/r4.md",
                "rules/sub/r5.md",
            ]
            for rel in rel_files:
                path = root / rel
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(f"# {rel}\n", encoding="utf-8")

            code, out, err = _run_cli(
                ["docs", "--repo", str(root), "--batch-mode", "single", "--dry-run", "--format", "json"],
            )
            self.assertEqual(code, 0, msg=err)
            report = json.loads(out)
            selected = [item["file"] for item in report["items"]]
            expected = sorted(
                [
                    "README.md",
                    "AGENTS.md",
                    "GEMINI.md",
                    "CLAUDE.md",
                    "docs/guide.md",
                    "skills/demo/SKILL.md",
                    "skills/demo/guidelines.md",
                    "skills/demo/references/api-reference.md",
                    ".agents/skills/helper/notes.md",
                    ".agents/rules/r1.md",
                    ".agent/rules/r2.md",
                    "_agents/rules/sub/r3.md",
                    "_agent/rules/r4.md",
                    "rules/sub/r5.md",
                ]
            )
            self.assertEqual(selected, expected)
            self.assertNotIn("CHANGELOG.md", selected)
            self.assertNotIn("skills/japanese-tech-writing/references/slop-catalog.md", selected)

    def test_SDD_17_explicit_paths_allows_slop_catalog(self) -> None:
        """SDD-17: 既定モードで除外される slop-catalog.md を明示的な --paths 指定で選択できる。"""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            catalog = root / "skills" / "japanese-tech-writing" / "references" / "slop-catalog.md"
            catalog.parent.mkdir(parents=True, exist_ok=True)
            catalog.write_text("# Catalog\n", encoding="utf-8")
            (root / "README.md").write_text("# Readme\n", encoding="utf-8")

            code_default, out_default, err_default = _run_cli(
                ["docs", "--repo", str(root), "--batch-mode", "single", "--dry-run", "--format", "json"],
            )
            self.assertEqual(code_default, 0, msg=err_default)
            default_files = [item["file"] for item in json.loads(out_default)["items"]]
            self.assertEqual(default_files, ["README.md"])

            code_explicit, out_explicit, err_explicit = _run_cli(
                [
                    "docs",
                    "--repo",
                    str(root),
                    "--paths",
                    "skills/japanese-tech-writing/references/slop-catalog.md",
                    "--batch-mode",
                    "single",
                    "--dry-run",
                    "--format",
                    "json",
                ],
            )
            self.assertEqual(code_explicit, 0, msg=err_explicit)
            explicit_files = [item["file"] for item in json.loads(out_explicit)["items"]]
            self.assertEqual(explicit_files, ["skills/japanese-tech-writing/references/slop-catalog.md"])


class BacklogModeTests(unittest.TestCase):
    def test_SDD_06_backlog_markdown_extraction_and_single_request_call(self) -> None:
        """SDD-06: backlog Markdown の未完了項目抽出と 1 リクエスト一括突合を検証する。"""
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

    def test_SDD_07_backlog_json_input_and_empty_skip(self) -> None:
        """SDD-07: backlog の空入力スキップと JSON 入力の dry-run を検証する。"""
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

    def test_SDD_08_backlog_exceeds_1000_questions_rejected(self) -> None:
        """SDD-08: backlog の質問数が 1,000 件を超えると終了コード 2 で拒否する。"""
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
    def test_SDD_09_input_and_stdin_mutual_exclusion(self) -> None:
        """SDD-09: candidates の --input と --stdin の排他検証を確認する。"""
        code_none, _, err_none = _run_cli(["candidates"])
        self.assertEqual(code_none, 2)
        self.assertIn("invalid_input_source", err_none)

        code_both, _, err_both = _run_cli(["candidates", "--input", "a.json", "--stdin"], stdin_text="[]")
        self.assertEqual(code_both, 2)
        self.assertIn("invalid_input_source", err_both)

    def test_SDD_10_empty_candidates_skipped_without_api_key(self) -> None:
        """SDD-10: candidates が空配列なら API キーなしで skipped_empty_input を返す。"""
        code, out, err = _run_cli(["candidates", "--stdin"], stdin_text="[]")
        self.assertEqual(code, 0, msg=err)
        self.assertEqual(json.loads(out)["status"], "skipped_empty_input")

    def test_SDD_11_candidates_parallel_order_and_parent_review_escalation(self) -> None:
        """SDD-11: candidates の並列実行順保持と要親確認エスカレーションを検証する。"""
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

        c2_finished = threading.Event()
        completion_order: list[str] = []
        lock = threading.Lock()

        def mock_opener(req: object, timeout: float = 30.0) -> _FakeHTTPResponse:
            body = json.loads(req.data.decode("utf-8"))  # type: ignore[attr-defined]
            text = body["input"][0]["text"]
            if "Candidate ID: C-1" in text:
                if not c2_finished.wait(timeout=2.0):
                    raise TimeoutError("C-2 did not complete concurrently within timeout")
                with lock:
                    completion_order.append("C-1")
                return _FakeHTTPResponse(
                    _make_candidate_response(discuss=0.10, route="plan_worker_autonomous", route_conf=0.92)
                )
            if "Candidate ID: C-2" in text:
                with lock:
                    completion_order.append("C-2")
                c2_finished.set()
                return _FakeHTTPResponse(
                    _make_candidate_response(discuss=0.65, route="plan_worker_discussion", route_conf=0.88)
                )
            with lock:
                completion_order.append("C-3")
            return _FakeHTTPResponse(
                _make_candidate_response(discuss=0.20, route="plan_worker_autonomous", route_conf=0.55)
            )

        code, out, err = _run_cli(
            ["candidates", "--stdin", "--batch-mode", "single", "--max-workers", "3", "--format", "json"],
            opener=mock_opener,
            env={"GEMINI_API_KEY": "test-dummy-key"},
            stdin_text=json.dumps(items, ensure_ascii=False),
        )
        self.assertEqual(code, 0, msg=err)
        report = json.loads(out)
        self.assertLess(completion_order.index("C-2"), completion_order.index("C-1"))
        self.assertEqual([r["id"] for r in report["results"]], ["C-1", "C-2", "C-3"])
        by_id = {r["id"]: r for r in report["results"]}
        self.assertFalse(by_id["C-1"]["needs_parent_review"])
        self.assertTrue(by_id["C-2"]["needs_parent_review"])
        self.assertIn("needs_discussion>=0.50", by_id["C-2"]["reasons"])
        self.assertTrue(by_id["C-3"]["needs_parent_review"])
        self.assertIn("low_confidence<0.80", by_id["C-3"]["reasons"])


class SecurityAndErrorHandlingTests(unittest.TestCase):
    def test_SDD_12_env_blocked_and_env_example_allowed(self) -> None:
        """SDD-12: .env の遮断と .env.example 雛形の許可を検証する。"""
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

    def test_SDD_13_secret_patterns_blocked_and_masked_before_api_call(self) -> None:
        """SDD-13: 秘密情報パターンを API 送信前に検出しマスクして遮断する。"""
        secrets = [
            "-----BEGIN " + "RSA PRIVATE KEY-----\nABC",
            "AIza" + "SyDummyGoogleApiKey1234567890",
            "ghp_" + ("DummyGitHubTokenValue" + "1234567890"),
            "github_pat_" + ("DummyFineGrainedToken" + "123456"),
            "sk-" + ("DummySecretKeyValue" + "1234567890"),
            "AKIA" + "IOSFODNN7EXAMPLE",
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

    def test_SDD_14_max_chars_limit_and_missing_api_key_and_key_masking(self) -> None:
        """SDD-14: 文字数上限、API キー欠如、エラー出力時のキーマスクを検証する。"""
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

    def test_SDD_15_safety_blocks_return_exit_code_3(self) -> None:
        """SDD-15: 安全フィルタ遮断（HTTP 400 / HTTP 200）が終了コード 3 を返す。"""
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

    def test_SDD_18_multiline_pem_block_masking_and_utf8_reconfigure(self) -> None:
        """SDD-18: 複数行 PEM ブロック全体マスクと main() 先頭での UTF-8 再設定を検証する。"""
        pem_begin = "-----BEGIN " + "RSA PRIVATE KEY-----"
        pem_end = "-----END " + "RSA PRIVATE KEY-----"
        pem_block = (
            f"{pem_begin}\n"
            "MIIEowIBAAKCAQEAsecretbodyline1\n"
            "secretbodyline2\n"
            f"{pem_end}"
        )
        masked_block = sdd.mask_secret(f"leak: {pem_block}\ntail")
        self.assertIn("[REDACTED]", masked_block)
        self.assertNotIn("MIIEowIBAAKCAQEAsecretbodyline1", masked_block)
        self.assertNotIn("secretbodyline2", masked_block)
        self.assertNotIn("BEGIN " + "RSA PRIVATE KEY", masked_block)
        self.assertNotIn("END " + "RSA PRIVATE KEY", masked_block)

        masked_header = sdd.mask_secret("-----BEGIN " + "PRIVATE KEY-----\npartial_unclosed")
        self.assertNotIn("BEGIN " + "PRIVATE KEY", masked_header)
        self.assertIn("[REDACTED]", masked_header)

        def pem_error_opener(req: object, timeout: float = 30.0) -> _FakeHTTPResponse:
            raise run_decisions.ApiRequestError(500, f"failed: {pem_block}")

        with tempfile.TemporaryDirectory() as tmp:
            root = _create_sample_repo(Path(tmp))
            (root / "README.md").write_text(
                "# チェック ✓ 日本語 — テスト\n",
                encoding="utf-8",
            )
            code_pem, _, err_pem = _run_cli(
                ["docs", "--repo", str(root), "--paths", "README.md"],
                opener=pem_error_opener,
                env={"GEMINI_API_KEY": "test-key"},
            )
            self.assertEqual(code_pem, 1)
            self.assertIn("[REDACTED]", err_pem)
            self.assertNotIn("secretbodyline2", err_pem)

            reconf_calls: list[str | None] = []

            class _ReconfigurableStringIO(io.StringIO):
                def reconfigure(self, *, encoding: str | None = None) -> None:
                    reconf_calls.append(encoding)

            out_stream = _ReconfigurableStringIO()
            err_stream = io.StringIO()
            with mock.patch.object(sys, "stdout", out_stream), mock.patch.object(sys, "stderr", err_stream):
                code_reconf = sdd.main(["docs", "--repo", str(root), "--dry-run"], env={})
            self.assertEqual(code_reconf, 0, msg=err_stream.getvalue())
            self.assertEqual(reconf_calls, ["utf-8"])

            sub_env = os.environ.copy()
            sub_env.pop("PYTHONUTF8", None)
            sub_env["PYTHONIOENCODING"] = "cp932"
            proc = subprocess.run(
                [
                    sys.executable,
                    "-B",
                    str(_SCRIPT_DIR / "screen_drift_decision1.py"),
                    "docs",
                    "--repo",
                    str(root),
                    "--dry-run",
                    "--format",
                    "json",
                ],
                capture_output=True,
                env=sub_env,
                check=False,
            )
            self.assertEqual(
                proc.returncode,
                0,
                msg=proc.stderr.decode("utf-8", errors="replace"),
            )
            stdout_text = proc.stdout.decode("utf-8")
            self.assertIn("チェック ✓ 日本語 — テスト", stdout_text)


class UpgradeFeaturesTests(unittest.TestCase):
    def test_SDD_19_docs_chunk_packing_usage_non_duplication_and_flag_hints(self) -> None:
        """SDD-19: docs チャンク既定がスナップショット 1 回共有・名前空間付きキー・usage 非重複加算・missing_flag_hints を満たす。"""
        with tempfile.TemporaryDirectory() as tmp:
            root = _create_sample_repo(Path(tmp))
            (root / "scripts").mkdir()
            (root / "scripts" / "tool.py").write_text(
                "import argparse\np = argparse.ArgumentParser()\np.add_argument('--repo')\n",
                encoding="utf-8",
            )
            (root / "docs" / "cli_guide.md").write_text(
                "# CLI Guide\n\n```bash\npython scripts/tool.py --repo . --nonexistent\n```\n",
                encoding="utf-8",
            )

            # 無効な --chunk-max-docs を拒否
            for bad_val in ("0", "167"):
                c_bad, _, e_bad = _run_cli(
                    ["docs", "--repo", str(root), "--chunk-max-docs", bad_val, "--dry-run"]
                )
                self.assertEqual(c_bad, 2)
                self.assertIn("invalid_chunk_max_docs", e_bad)

            # --chunk-max-docs 2 で 4 文書が 2 チャンクへ分割されること
            c_dry, o_dry, e_dry = _run_cli(
                ["docs", "--repo", str(root), "--chunk-max-docs", "2", "--dry-run", "--format", "json"]
            )
            self.assertEqual(c_dry, 0, msg=e_dry)
            dry_report = json.loads(o_dry)
            self.assertEqual(dry_report["batch_mode"], "chunk")
            self.assertEqual(dry_report["total"], 4)
            self.assertEqual(dry_report["chunk_count"], 2)
            ch0_payload = dry_report["chunks"][0]["payload"]
            self.assertEqual(len(ch0_payload["input"]), 3)  # snapshot 1 + docs 2
            self.assertIn("Repository Root:", ch0_payload["input"][0]["text"])
            self.assertIn("Target document [doc_0001]: README.md", ch0_payload["questions"]["doc_0001__stale_status_or_facts"]["instructions"])

            captured_requests: list[dict[str, object]] = []

            def chunk_opener(req: object, timeout: float = 30.0) -> _FakeHTTPResponse:
                body = json.loads(req.data.decode("utf-8"))  # type: ignore[attr-defined]
                captured_requests.append(body)
                q_keys = list(body["questions"].keys())
                namespaces = sorted({k.split("__", 1)[0] for k in q_keys})
                answers: dict[str, object] = {}
                for ns in namespaces:
                    base = _make_docs_response(action="likely_clean", action_conf=0.95)
                    for qk, qv in base["answers"].items():  # type: ignore[union-attr]
                        answers[f"{ns}__{qk}"] = qv
                return _FakeHTTPResponse(
                    {
                        "answers": answers,
                        "usage": {
                            "total_input_tokens": 500,
                            "total_output_tokens": 0,
                            "total_tokens": 500,
                        },
                    }
                )

            code, out, err = _run_cli(
                ["docs", "--repo", str(root), "--chunk-max-docs", "4", "--format", "json"],
                opener=chunk_opener,
                env={"GEMINI_API_KEY": "test-dummy-key"},
            )
            self.assertEqual(code, 0, msg=err)
            self.assertEqual(len(captured_requests), 1)
            report = json.loads(out)
            self.assertEqual(report["total"], 4)
            # 1 チャンク = 500 トークンであり、4 文書倍の 2000 になってはならない
            self.assertEqual(report["usage"]["total_input_tokens"], 500)
            self.assertEqual(report["usage"]["total_tokens"], 500)

            by_file = {r["file"]: r for r in report["results"]}
            self.assertEqual(by_file["docs/cli_guide.md"]["missing_flag_hints"], ["tool.py:--nonexistent"])
            self.assertEqual(by_file["docs/cli_guide.md"]["bucket"], "prioritize_for_audit")
            self.assertIn("missing_flag_hints(1)", by_file["docs/cli_guide.md"]["reasons"])
            self.assertEqual(by_file["docs/clean.md"]["bucket"], "low_priority_clean")

    def test_SDD_20_backlog_heading_breadcrumbs_in_items_instructions_and_table(self) -> None:
        """SDD-20: backlog が見出しパンくずを section・instructions・table 出力へ反映する。"""
        with tempfile.TemporaryDirectory() as tmp:
            root = _create_sample_repo(Path(tmp))
            bl = root / "BACKLOG.md"
            bl.write_text(
                "# Phase 1\n"
                "## Backend\n"
                "### Auth\n"
                "- [ ] Fix token refresh\n"
                "## Frontend\n"
                "- [ ] Align button spacing\n",
                encoding="utf-8",
            )
            code, out, err = _run_cli(
                ["backlog", "--backlog", str(bl), "--repo", str(root), "--dry-run", "--format", "json"]
            )
            self.assertEqual(code, 0, msg=err)
            report = json.loads(out)
            items = report["items"]
            self.assertEqual(items[0]["section"], "Phase 1 > Backend > Auth")
            self.assertEqual(items[1]["section"], "Phase 1 > Frontend")
            q1_inst = report["payload"]["questions"][items[0]["question_key"]]["instructions"]
            self.assertIn("Section: Phase 1 > Backend > Auth", q1_inst)

            code_t, out_t, err_t = _run_cli(
                ["backlog", "--backlog", str(bl), "--repo", str(root), "--dry-run", "--format", "table"]
            )
            self.assertEqual(code_t, 0, msg=err_t)
            self.assertIn("| section |", out_t)
            self.assertIn("Phase 1 > Backend > Auth", out_t)

    def test_SDD_21_backlog_table_parser_auto_fallback_and_include_tables(self) -> None:
        """SDD-21: backlog 表パーサが状態列の未完了行のみ抽出し、auto フォールバックと --include-tables を制御する。"""
        with tempfile.TemporaryDirectory() as tmp:
            root = _create_sample_repo(Path(tmp))
            table_only = root / "TABLE_ONLY.md"
            table_only.write_text(
                "# Release Ledger\n\n"
                "| ID | Task | Status |\n"
                "| --- | --- | --- |\n"
                "| T-1 | Migrate auth | 未着手 |\n"
                "| T-2 | Old fix | 完了 |\n"
                "| T-3 | Update docs | In Progress |\n"
                "| T-4 | Archived | done |\n"
                "| T-5 | Stalled | blocked |\n\n"
                "## Non-status table\n\n"
                "| Name | Owner |\n"
                "| --- | --- |\n"
                "| Alpha | Alice |\n",
                encoding="utf-8",
            )
            code, out, err = _run_cli(
                ["backlog", "--backlog", str(table_only), "--repo", str(root), "--dry-run", "--format", "json"]
            )
            self.assertEqual(code, 0, msg=err)
            items = json.loads(out)["items"]
            self.assertEqual(len(items), 3)
            self.assertIn("T-1 | Migrate auth", items[0]["text"])
            self.assertIn("T-3 | Update docs", items[1]["text"])
            self.assertIn("T-5 | Stalled", items[2]["text"])
            self.assertEqual(items[0]["section"], "Release Ledger")

            mixed = root / "MIXED.md"
            mixed.write_text(
                "# Mixed\n\n"
                "- [ ] Checkbox task\n\n"
                "| Item | 状態 |\n"
                "| --- | --- |\n"
                "| Table task | 進行中 |\n"
                "| Done task | 済み |\n",
                encoding="utf-8",
            )
            # auto ではチェックボックス優先（1 件）
            c_auto, o_auto, e_auto = _run_cli(
                ["backlog", "--backlog", str(mixed), "--repo", str(root), "--dry-run", "--format", "json"]
            )
            self.assertEqual(c_auto, 0, msg=e_auto)
            self.assertEqual(json.loads(o_auto)["total"], 1)

            # --include-tables で両方抽出（2 件）
            c_inc, o_inc, e_inc = _run_cli(
                [
                    "backlog",
                    "--backlog",
                    str(mixed),
                    "--repo",
                    str(root),
                    "--include-tables",
                    "--dry-run",
                    "--format",
                    "json",
                ]
            )
            self.assertEqual(c_inc, 0, msg=e_inc)
            inc_items = json.loads(o_inc)["items"]
            self.assertEqual(len(inc_items), 2)
            self.assertIn("Checkbox task", inc_items[0]["text"])
            self.assertIn("Table task", inc_items[1]["text"])

            # --backlog-format table で表のみ抽出（1 件）
            c_tbl, o_tbl, e_tbl = _run_cli(
                [
                    "backlog",
                    "--backlog",
                    str(mixed),
                    "--backlog-format",
                    "table",
                    "--repo",
                    str(root),
                    "--dry-run",
                    "--format",
                    "json",
                ]
            )
            self.assertEqual(c_tbl, 0, msg=e_tbl)
            tbl_items = json.loads(o_tbl)["items"]
            self.assertEqual(len(tbl_items), 1)
            self.assertIn("Table task", tbl_items[0]["text"])

    def test_SDD_22_candidates_chunk_mode_with_repo_and_usage_non_duplication(self) -> None:
        """SDD-22: candidates チャンクモードが --repo 共有スナップショット・chunk 分割・usage 非重複加算を満たす。"""
        with tempfile.TemporaryDirectory() as tmp:
            root = _create_sample_repo(Path(tmp))
            cands = [
                {
                    "id": f"C-{i}",
                    "category": "doc_drift",
                    "title": f"Item {i}",
                    "files": ["README.md"],
                    "evidence": f"ev {i}",
                    "symptom": f"sym {i}",
                }
                for i in range(1, 4)
            ]

            c_bad, _, e_bad = _run_cli(
                ["candidates", "--stdin", "--chunk-max-items", "201", "--dry-run"],
                stdin_text=json.dumps(cands),
            )
            self.assertEqual(c_bad, 2)
            self.assertIn("invalid_chunk_max_items", e_bad)

            c_dry, o_dry, e_dry = _run_cli(
                [
                    "candidates",
                    "--stdin",
                    "--repo",
                    str(root),
                    "--chunk-max-items",
                    "2",
                    "--dry-run",
                    "--format",
                    "json",
                ],
                stdin_text=json.dumps(cands),
            )
            self.assertEqual(c_dry, 0, msg=e_dry)
            dry_report = json.loads(o_dry)
            self.assertEqual(dry_report["batch_mode"], "chunk")
            self.assertEqual(dry_report["chunk_count"], 2)
            self.assertEqual(dry_report["chunks"][0]["ids"], ["C-1", "C-2"])
            self.assertIn("Repository Root:", dry_report["chunks"][0]["payload"]["input"][0]["text"])
            self.assertIn("cand_0001__fits_single_track", dry_report["chunks"][0]["payload"]["questions"])

            calls = 0

            def cand_chunk_opener(req: object, timeout: float = 30.0) -> _FakeHTTPResponse:
                nonlocal calls
                calls += 1
                body = json.loads(req.data.decode("utf-8"))  # type: ignore[attr-defined]
                namespaces = sorted({k.split("__", 1)[0] for k in body["questions"]})
                answers: dict[str, object] = {}
                for ns in namespaces:
                    base = _make_candidate_response(
                        discuss=0.10,
                        route="plan_worker_autonomous",
                        route_conf=0.92,
                    )
                    for qk, qv in base["answers"].items():  # type: ignore[union-attr]
                        answers[f"{ns}__{qk}"] = qv
                return _FakeHTTPResponse(
                    {
                        "answers": answers,
                        "usage": {
                            "total_input_tokens": 600,
                            "total_output_tokens": 0,
                            "total_tokens": 600,
                        },
                    }
                )

            c_ok, o_ok, e_ok = _run_cli(
                ["candidates", "--stdin", "--repo", str(root), "--chunk-max-items", "10", "--format", "json"],
                opener=cand_chunk_opener,
                env={"GEMINI_API_KEY": "test-dummy-key"},
                stdin_text=json.dumps(cands),
            )
            self.assertEqual(c_ok, 0, msg=e_ok)
            self.assertEqual(calls, 1)
            report = json.loads(o_ok)
            self.assertEqual(report["total"], 3)
            self.assertEqual(report["usage"]["total_input_tokens"], 600)
            self.assertEqual(report["usage"]["total_tokens"], 600)

    def test_SDD_23_backend_routing_auto_sdk_and_rest(self) -> None:
        """SDD-23: --backend {auto,sdk,rest} が call_decisions_backend 経由で正しく振り分けられる。"""
        cand = [
            {
                "id": "C-1",
                "category": "doc_drift",
                "title": "Check backend",
                "evidence": "ev",
                "symptom": "sym",
            }
        ]
        # opener 指定時の auto -> rest
        def rest_opener(req: object, timeout: float = 30.0) -> _FakeHTTPResponse:
            return _FakeHTTPResponse(
                {
                    "answers": {
                        f"cand_0001__{k}": v
                        for k, v in _make_candidate_response()["answers"].items()  # type: ignore[union-attr]
                    },
                    "usage": {"total_input_tokens": 10, "total_output_tokens": 0, "total_tokens": 10},
                }
            )

        code_rest, out_rest, err_rest = _run_cli(
            ["candidates", "--stdin", "--backend", "auto"],
            opener=rest_opener,
            env={"GEMINI_API_KEY": "k"},
            stdin_text=json.dumps(cand),
        )
        self.assertEqual(code_rest, 0, msg=err_rest)
        self.assertEqual(json.loads(out_rest)["backend"], "rest")

        # --backend sdk でモックされた call_decisions_backend 経由 SDK 応答を返す
        sdk_resp = {
            "answers": {
                f"cand_0001__{k}": v
                for k, v in _make_candidate_response()["answers"].items()  # type: ignore[union-attr]
            },
            "usage": {"total_input_tokens": 20, "total_output_tokens": 0, "total_tokens": 20},
        }
        with mock.patch.object(
            run_decisions,
            "call_decisions_backend",
            return_value=(sdk_resp, "sdk"),
        ) as patched_backend:
            code_sdk, out_sdk, err_sdk = _run_cli(
                ["candidates", "--stdin", "--backend", "sdk"],
                env={"GEMINI_API_KEY": "k"},
                stdin_text=json.dumps(cand),
            )
        self.assertEqual(code_sdk, 0, msg=err_sdk)
        self.assertEqual(json.loads(out_sdk)["backend"], "sdk")
        self.assertEqual(patched_backend.call_args.kwargs["backend"], "sdk")

    def test_SDD_24_broken_pipe_exits_zero_without_error_json(self) -> None:
        """SDD-24: screen_drift_decision1.py のパイプ切断（BrokenPipeError / Windows EINVAL）がエラー JSON なしで終了コード 0 になる。"""
        class _BrokenStream:
            def __init__(self, exc: BaseException) -> None:
                self._exc = exc

            def write(self, _text: str) -> int:
                raise self._exc

            def flush(self) -> None:
                pass

        with tempfile.TemporaryDirectory() as tmp:
            root = _create_sample_repo(Path(tmp))
            for exc in (BrokenPipeError(errno.EPIPE, "broken"), OSError(errno.EINVAL, "einval")):
                if type(exc) is OSError and os.name != "nt":
                    continue
                err_buf = io.StringIO()
                broken_stream = _BrokenStream(exc)
                with mock.patch.object(sys, "stdout", broken_stream), redirect_stderr(err_buf):
                    try:
                        code = sdd.main(["docs", "--repo", str(root), "--dry-run"], env={})
                    finally:
                        if sys.stdout is not broken_stream and getattr(sys.stdout, "name", None) == os.devnull:
                            sys.stdout.close()
                self.assertEqual(code, 0)
                self.assertEqual(err_buf.getvalue(), "")

    def test_SDD_25_facade_reexports_drift_repo_and_drift_format(self) -> None:
        """SDD-25: screen_drift_decision1.py が drift_repo と drift_format の公開シンボルを再エクスポートする。"""
        expected_symbols = (
            "DEFAULT_MODEL",
            "DEFAULT_ENDPOINT",
            "DRIFT_SEVERITY_CRITERIA",
            "CANDIDATES_IMPACT_CRITERIA",
            "DriftScreenError",
            "RepoContext",
            "DocEntry",
            "BacklogItem",
            "AuditCandidate",
            "collect_repo_context",
            "compute_staleness_days",
            "compute_staleness_days_bulk",
            "extract_missing_path_hints",
            "extract_missing_flag_hints",
            "mask_secret",
            "format_report_table",
            "emit_report",
            "emit_error",
        )
        for sym in expected_symbols:
            self.assertTrue(hasattr(sdd, sym), msg=f"missing facade symbol: {sym}")

    def test_SDD_26_subprocess_broken_pipe_exits_zero(self) -> None:
        """SDD-26: 実子プロセスでパイプ読み端を早期クローズしたとき screen_drift_decision1.py が終了コード 0 を返す。"""
        with tempfile.TemporaryDirectory() as tmp:
            root = _create_sample_repo(Path(tmp))
            # OS パイプバッファを超えるサイズにして書き込み中のパイプ切断を確実に発生させる
            (root / "README.md").write_text(
                "# Large\n\n" + ("word " * 25000) + "\n",
                encoding="utf-8",
            )
            sub_env = os.environ.copy()
            sub_env["PYTHONUTF8"] = "1"
            sub_env["PYTHONIOENCODING"] = "utf-8"
            proc = subprocess.Popen(
                [
                    sys.executable,
                    "-B",
                    str(_SCRIPT_DIR / "screen_drift_decision1.py"),
                    "docs",
                    "--repo",
                    str(root),
                    "--paths",
                    "README.md",
                    "--dry-run",
                    "--format",
                    "table",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=sub_env,
            )
            assert proc.stdout is not None and proc.stderr is not None
            proc.stdout.read(1)
            proc.stdout.close()
            proc.stdout = None
            try:
                _, stderr_bytes = proc.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
                _, stderr_bytes = proc.communicate()
                raise
            self.assertEqual(proc.returncode, 0, msg=stderr_bytes.decode("utf-8", errors="replace"))
            self.assertEqual(stderr_bytes, b"")

    def test_SDD_27_backlog_checkbox_immediately_after_table_preserved(self) -> None:
        """SDD-27: 状態表の直後に空行なしで `- [ ] Document A | B` がある場合に取りこぼさない。"""
        with tempfile.TemporaryDirectory() as tmp:
            root = _create_sample_repo(Path(tmp))
            bl = root / "BACKLOG.md"
            bl.write_text(
                "# Ledger\n\n"
                "| ID | Task | Status |\n"
                "| --- | --- | --- |\n"
                "| T-1 | Table pending item | 未着手 |\n"
                "- [ ] Document A | B\n",
                encoding="utf-8",
            )
            code, out, err = _run_cli(
                [
                    "backlog",
                    "--backlog",
                    str(bl),
                    "--repo",
                    str(root),
                    "--include-tables",
                    "--dry-run",
                    "--format",
                    "json",
                ]
            )
            self.assertEqual(code, 0, msg=err)
            items = json.loads(out)["items"]
            self.assertEqual(len(items), 2)
            self.assertIn("T-1 | Table pending item", items[0]["text"])
            self.assertEqual(items[1]["text"], "Document A | B")

    def test_SDD_28_explicit_timeout_forces_rest_on_auto_and_rejects_sdk(self) -> None:
        """SDD-28: 明示 --timeout 指定時に auto は REST 経路を選び、sdk は終了コード 2 で拒否される。"""
        cand = json.dumps(
            [
                {
                    "id": "C-1",
                    "category": "doc_drift",
                    "title": "Check timeout backend",
                    "evidence": "ev",
                    "symptom": "sym",
                }
            ]
        )

        code_sdk, _, err_sdk = _run_cli(
            ["candidates", "--stdin", "--backend", "sdk", "--timeout", "5"],
            env={"GEMINI_API_KEY": "k"},
            stdin_text=cand,
        )
        self.assertEqual(code_sdk, 2)
        self.assertIn("invalid_argument", err_sdk)

        captured: list[dict[str, object]] = []

        def fake_backend(payload: dict[str, object], **kwargs: object) -> tuple[dict[str, object], str]:
            captured.append(dict(kwargs))
            resp = {
                "answers": {
                    f"cand_0001__{k}": v
                    for k, v in _make_candidate_response()["answers"].items()  # type: ignore[union-attr]
                },
                "usage": {"total_input_tokens": 10, "total_output_tokens": 0, "total_tokens": 10},
            }
            return resp, str(kwargs["backend"])

        with mock.patch.object(run_decisions, "call_decisions_backend", side_effect=fake_backend):
            code_auto, out_auto, err_auto = _run_cli(
                ["candidates", "--stdin", "--backend", "auto", "--timeout", "5"],
                env={"GEMINI_API_KEY": "k"},
                stdin_text=cand,
            )
        self.assertEqual(code_auto, 0, msg=err_auto)
        self.assertEqual(captured[0]["backend"], "rest")
        self.assertEqual(captured[0]["timeout"], 5.0)
        self.assertEqual(json.loads(out_auto)["backend"], "rest")

        captured.clear()
        with mock.patch.object(run_decisions, "call_decisions_backend", side_effect=fake_backend):
            code_def, _, err_def = _run_cli(
                ["candidates", "--stdin", "--backend", "auto"],
                env={"GEMINI_API_KEY": "k"},
                stdin_text=cand,
            )
        self.assertEqual(code_def, 0, msg=err_def)
        self.assertEqual(captured[0]["backend"], "auto")
        self.assertEqual(captured[0]["timeout"], sdd.DEFAULT_TIMEOUT)

    def test_SDD_29_rest_read_timeout_returns_exit_code_1(self) -> None:
        """SDD-29: REST 応答読み取り中の TimeoutError が exit code 2 ではなく exit code 1 (api_request_failed) を返す。"""
        cand = json.dumps(
            [
                {
                    "id": "C-1",
                    "category": "doc_drift",
                    "title": "Check read timeout",
                    "evidence": "ev",
                    "symptom": "sym",
                }
            ]
        )
        secret_key = "SUPER_SECRET_TIMEOUT_KEY"

        class _TimeoutResponse:
            def read(self) -> bytes:
                raise TimeoutError(f"timed out with key={secret_key}")

            def __enter__(self) -> "_TimeoutResponse":
                return self

            def __exit__(self, exc_type: object, exc: object, tb: object) -> bool:
                return False

        def timeout_opener(req: object, timeout: float = 30.0) -> _TimeoutResponse:
            return _TimeoutResponse()

        code, _, err = _run_cli(
            ["candidates", "--stdin", "--backend", "rest", "--timeout", "2"],
            opener=timeout_opener,
            env={"GEMINI_API_KEY": secret_key},
            stdin_text=cand,
        )
        self.assertEqual(code, 1)
        self.assertIn("api_request_failed", err)
        self.assertNotIn(secret_key, err)
        self.assertIn("[REDACTED]", err)


if __name__ == "__main__":
    unittest.main()
