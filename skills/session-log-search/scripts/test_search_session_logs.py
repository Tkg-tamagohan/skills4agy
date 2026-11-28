#!/usr/bin/env python3
"""search_session_logs.py のユニットテスト（SL-01〜SL-14）。"""

from __future__ import annotations

import contextlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

_THIS_DIR = Path(__file__).resolve().parent
if str(_THIS_DIR) not in sys.path:
    sys.path.insert(0, str(_THIS_DIR))

import search_session_logs as mod  # noqa: E402


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")


def _make_user(step_index: int, text: str, created_at: str) -> dict:
    return {
        "step_index": step_index,
        "source": "USER_EXPLICIT",
        "type": "USER_INPUT",
        "status": "DONE",
        "created_at": created_at,
        "content": f"<USER_REQUEST>\n{text}\n</USER_REQUEST>",
    }


def _make_planner(
    step_index: int,
    content: str,
    created_at: str,
    *,
    tool_calls: list[dict] | None = None,
    thinking: str = "",
) -> dict:
    row: dict = {
        "step_index": step_index,
        "source": "MODEL",
        "type": "PLANNER_RESPONSE",
        "status": "DONE",
        "created_at": created_at,
        "content": content,
    }
    if tool_calls is not None:
        row["tool_calls"] = tool_calls
    if thinking:
        row["thinking"] = thinking
    return row


def _make_generic(
    step_index: int,
    content: str,
    created_at: str,
    *,
    status: str = "DONE",
    truncated_fields: list[str] | None = None,
) -> dict:
    row: dict = {
        "step_index": step_index,
        "source": "MODEL",
        "type": "GENERIC",
        "status": status,
        "created_at": created_at,
        "content": content,
    }
    if truncated_fields is not None:
        row["truncated_fields"] = truncated_fields
    return row


def _make_system(step_index: int, content: str, created_at: str) -> dict:
    return {
        "step_index": step_index,
        "source": "SYSTEM",
        "type": "SYSTEM_MESSAGE",
        "status": "DONE",
        "created_at": created_at,
        "content": content,
    }


class SearchSessionLogsTests(unittest.TestCase):
    def _run_main_json(self, args: list[str]) -> tuple[int, dict]:
        buf = io.StringIO()
        err = io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(err):
            rc = mod.main(args)
        data = json.loads(buf.getvalue()) if buf.getvalue().strip() else {}
        return rc, data

    def test_sl01_two_char_japanese_both_paths(self) -> None:
        """SL-01: 'なぜ'・'却下' の 2 文字日本語で Python 経路と rg 経路の両方がヒットする。"""
        with tempfile.TemporaryDirectory() as tmp:
            app_dir = Path(tmp)
            tp = app_dir / "brain" / "conv-jp-01" / ".system_generated" / "logs" / "transcript.jsonl"
            _write_jsonl(
                tp,
                [
                    _make_user(0, "データベース選定の方針を教えてください", "2026-11-20T10:00:00Z"),
                    _make_planner(1, "SQLite FTS5 単体案は却下しました。なぜなら 2 文字日本語で取りこぼすためです。", "2026-11-20T10:01:00Z"),
                ],
            )

            rc_py, data_py = self._run_main_json(
                ["--app-data-dir", str(app_dir), "--no-rg", "--format", "json", "--", "なぜ", "却下"]
            )
            self.assertEqual(rc_py, 0)
            self.assertFalse(data_py["used_rg"])
            self.assertGreaterEqual(data_py["restored_turns"], 1)
            self.assertIn("conv-jp-01", [r["conv_id"] for r in data_py["results"]])

            if shutil.which("rg"):
                rc_rg, data_rg = self._run_main_json(
                    ["--app-data-dir", str(app_dir), "--format", "json", "--", "なぜ", "却下"]
                )
                self.assertEqual(rc_rg, 0)
                self.assertTrue(data_rg["used_rg"])
                self.assertGreaterEqual(data_rg["restored_turns"], 1)
                self.assertIn("conv-jp-01", [r["conv_id"] for r in data_rg["results"]])

    def test_sl02_hyphen_leading_term_no_exit2(self) -> None:
        """SL-02: ハイフン始まりの --min-steps を渡しても rg exit 2 を起こさずヒットする。"""
        with tempfile.TemporaryDirectory() as tmp:
            app_dir = Path(tmp)
            tp = app_dir / "brain" / "conv-flag-01" / ".system_generated" / "logs" / "transcript.jsonl"
            _write_jsonl(
                tp,
                [
                    _make_user(0, "CLI フラグの使い方を確認したい", "2026-11-20T11:00:00Z"),
                    _make_planner(1, "通常は --min-steps 80 を付けて実行します。", "2026-11-20T11:01:00Z"),
                ],
            )
            rc, data = self._run_main_json(
                ["--app-data-dir", str(app_dir), "--format", "json", "--", "--min-steps"]
            )
            self.assertEqual(rc, 0)
            self.assertEqual(data["warnings"], [])
            primaries = [r for r in data["results"] if r["role"] == "primary"]
            self.assertEqual(len(primaries), 1)
            self.assertIn("--min-steps", primaries[0]["text"])

    def test_sl03_strict_blocklist_mixed_directory(self) -> None:
        """SL-03: ブロック対象ファイル群が混在しても一切列挙・出力されない。"""
        with tempfile.TemporaryDirectory() as tmp:
            app_dir = Path(tmp)
            brain_dir = app_dir / "brain"
            needle = "UNIQUE_NEEDLE_BLOCKLIST_CHECK"

            # 有効ファイル
            valid_tp = brain_dir / "conv-valid" / ".system_generated" / "logs" / "transcript.jsonl"
            _write_jsonl(valid_tp, [_make_user(0, f"正当な記録 {needle}", "2026-11-20T12:00:00Z")])

            # ブロック対象ファイル群
            blocked_files = [
                brain_dir / "conv-blocked" / ".system_generated" / "logs" / "chunks" / "chunk_0001.json",
                brain_dir / "conv-blocked" / ".system_generated" / "steps" / "step_0001.json",
                brain_dir / "conv-blocked" / ".system_generated" / "logs" / "conversation_summaries.db",
                brain_dir / "conv-blocked" / ".system_generated" / "logs" / "conversation_summaries.db-wal",
                app_dir / "conversations" / "state.db",
                brain_dir / "conv-blocked" / "state.pb",
                app_dir / "oauth_creds.json",
                app_dir / "google_accounts.json",
                brain_dir / "conv-blocked" / ".env",
                brain_dir / "conv-blocked" / ".env.local",
            ]
            for bf in blocked_files:
                bf.parent.mkdir(parents=True, exist_ok=True)
                bf.write_text(f"secret {needle}\n", encoding="utf-8")

            sources = mod.enumerate_sources(app_dir)
            source_paths = {str(s.path) for s in sources if s.path is not None}
            self.assertEqual(len(source_paths), 1)
            self.assertIn(str(valid_tp), source_paths)
            for bf in blocked_files:
                self.assertTrue(mod.is_blocked_path(bf), f"should be blocked: {bf}")

            # 許容される .env.example はブロックしない
            self.assertFalse(mod.is_blocked_path(brain_dir / "conv-valid" / ".env.example"))

            rc, data = self._run_main_json(
                ["--app-data-dir", str(app_dir), "--format", "json", "--", needle]
            )
            self.assertEqual(rc, 0)
            self.assertEqual(data["candidate_sources"], 1)
            self.assertEqual([r["conv_id"] for r in data["results"]], ["conv-valid"])

    def test_sl04_rewind_step_index_uses_line_idx(self) -> None:
        """SL-04: UI 巻き戻しで step_index が重複しても物理 line_idx で別ターンとして区別される。"""
        with tempfile.TemporaryDirectory() as tmp:
            app_dir = Path(tmp)
            tp = app_dir / "brain" / "conv-rewind" / ".system_generated" / "logs" / "transcript.jsonl"
            _write_jsonl(
                tp,
                [
                    _make_user(0, "最初の指示 REWIND_TOKEN_ALPHA", "2026-11-20T10:00:00Z"),
                    _make_planner(1, "最初の応答です", "2026-11-20T10:01:00Z"),
                    # UI 巻き戻しにより step_index が 0 から再採番されたケース
                    _make_user(0, "やり直し後の指示 REWIND_TOKEN_ALPHA", "2026-11-20T10:05:00Z"),
                    _make_planner(1, "やり直し後の応答です", "2026-11-20T10:06:00Z"),
                ],
            )
            rc, data = self._run_main_json(
                ["--app-data-dir", str(app_dir), "--format", "json", "--", "REWIND_TOKEN_ALPHA"]
            )
            self.assertEqual(rc, 0)
            primaries = [r for r in data["results"] if r["role"] == "primary"]
            self.assertEqual(len(primaries), 2)
            self.assertEqual([p["line_idx"] for p in primaries], [0, 2])
            self.assertEqual([p["step_index"] for p in primaries], [0, 0])

    def test_sl05_bearer_secret_masked_across_window_and_excerpt_boundaries(self) -> None:
        """SL-05: 窓境界や抜粋境界をまたぐ位置の Bearer トークンも断片を残さずマスクされる。"""
        with tempfile.TemporaryDirectory() as tmp:
            app_dir = Path(tmp)
            tp = app_dir / "brain" / "conv-secret" / ".system_generated" / "logs" / "transcript.jsonl"
            secret_val = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"
            bearer = f"Bearer {secret_val}"
            # 768 文字境界（750 文字目付近）と 400 文字境界の両方をテストできるよう長文を構成
            pad_a = "A" * 740
            pad_b = "B" * 420
            content = (
                f"{pad_a} {bearer} SECRET_QUERY_MARKER "
                f"{pad_b} Authorization: Bearer {secret_val} "
                f"https://admin:{secret_val}@example.com/api"
            )
            _write_jsonl(
                tp,
                [_make_planner(0, content, "2026-11-20T13:00:00Z")],
            )
            rc, data = self._run_main_json(
                [
                    "--app-data-dir",
                    str(app_dir),
                    "--budget-tokens",
                    "180",
                    "--format",
                    "json",
                    "--",
                    "SECRET_QUERY_MARKER",
                ]
            )
            self.assertEqual(rc, 0)
            rendered = data["results"][0]["text"]
            self.assertIn("[REDACTED]", rendered)
            # トークン実値の一部（先頭/末尾 8 文字）すら漏洩しないことを検証
            self.assertNotIn(secret_val[:8], rendered)
            self.assertNotIn(secret_val[-8:], rendered)
            self.assertNotIn("admin:", rendered)

    def test_sl06_budget_fallback_preserves_primary_and_chronological_order(self) -> None:
        """SL-06: 予算超過時は主ヒット数を削減せず抜粋へフォールバックし時系列昇順で出力する。"""
        with tempfile.TemporaryDirectory() as tmp:
            app_dir = Path(tmp)
            for idx, ts in enumerate(
                ["2026-11-22T10:00:00Z", "2026-11-20T10:00:00Z", "2026-11-21T10:00:00Z"]
            ):
                tp = app_dir / "brain" / f"conv-big-{idx}" / ".system_generated" / "logs" / "transcript.jsonl"
                long_text = ("X" * 1500) + f" BUDGET_NEEDLE_WORD " + ("Y" * 1500)
                _write_jsonl(tp, [_make_planner(0, long_text, ts)])

            rc, data = self._run_main_json(
                [
                    "--app-data-dir",
                    str(app_dir),
                    "--max-primary",
                    "3",
                    "--budget-tokens",
                    "1000",
                    "--format",
                    "json",
                    "--",
                    "BUDGET_NEEDLE_WORD",
                ]
            )
            self.assertEqual(rc, 0)
            self.assertTrue(data["fallback"])
            self.assertEqual(len(data["results"]), 3)
            self.assertTrue(all(r["excerpted"] for r in data["results"]))
            self.assertEqual(
                [r["created_at"] for r in data["results"]],
                ["2026-11-20T10:00:00Z", "2026-11-21T10:00:00Z", "2026-11-22T10:00:00Z"],
            )

    def test_sl07_excludes_noise_tools_trivial_exit0_and_self_search(self) -> None:
        """SL-07: read_file/update_focus の GENERIC、短小 exit-0、自己検索呼び出しが索引されない。"""
        with tempfile.TemporaryDirectory() as tmp:
            app_dir = Path(tmp)
            tp = app_dir / "brain" / "conv-noise" / ".system_generated" / "logs" / "transcript.jsonl"
            needle = "NOISE_FILTER_TOKEN"
            _write_jsonl(
                tp,
                [
                    _make_planner(
                        0,
                        "ファイルを読み込み進捗を更新します",
                        "2026-11-20T14:00:00Z",
                        tool_calls=[
                            {"name": "read_file", "args": {"Path": "foo.py"}},
                            {"name": "update_focus", "args": {"focus": "調査中"}},
                            {
                                "name": "run_command",
                                "args": {
                                    "CommandLine": f"python search_session_logs.py -- {needle}"
                                },
                            },
                            {"name": "run_command", "args": {"CommandLine": "echo ok"}},
                        ],
                    ),
                    _make_generic(1, f"Showing lines 1-50\n{needle}", "2026-11-20T14:00:01Z"),
                    _make_generic(2, f"OK {needle}", "2026-11-20T14:00:02Z"),
                    _make_generic(
                        3,
                        f"# Session Log Search Results\n{needle}\n" + ("Z" * 100),
                        "2026-11-20T14:00:03Z",
                    ),
                    _make_generic(
                        4,
                        f"Command exited with code 0\nCommand output:\nok {needle}",
                        "2026-11-20T14:00:04Z",
                    ),
                ],
            )
            rc, data = self._run_main_json(
                ["--app-data-dir", str(app_dir), "--format", "json", "--", needle]
            )
            self.assertEqual(rc, 0)
            self.assertEqual(data["restored_turns"], 0)

    def test_sl08_system_message_preserves_tool_alignment(self) -> None:
        """SL-08: SYSTEM_MESSAGE が間に挟まっても tool_calls[k] と GENERIC の対応がずれない。"""
        with tempfile.TemporaryDirectory() as tmp:
            app_dir = Path(tmp)
            tp = app_dir / "brain" / "conv-align" / ".system_generated" / "logs" / "transcript.jsonl"
            _write_jsonl(
                tp,
                [
                    _make_planner(
                        0,
                        "ファイル確認後にテストを実行します",
                        "2026-11-20T15:00:00Z",
                        tool_calls=[
                            {"name": "read_file", "args": {"Path": "a.py"}},
                            {"name": "run_command", "args": {"CommandLine": "pytest"}},
                        ],
                    ),
                    _make_system(1, "Reminder: work efficiently.", "2026-11-20T15:00:01Z"),
                    # k=0: read_file (除外されるべき)
                    _make_generic(2, "Showing lines 1-10\nALIGN_ONLY_READ_NOISE", "2026-11-20T15:00:02Z"),
                    _make_system(3, "Another system reminder.", "2026-11-20T15:00:03Z"),
                    # k=1: run_command (保持されるべき)
                    _make_generic(
                        4,
                        "Command exited with code 1\nAssertionError: ALIGN_CMD_KEEP_TARGET failed in test_x with details",
                        "2026-11-20T15:00:04Z",
                        status="ERROR",
                    ),
                ],
            )
            rc_noise, d_noise = self._run_main_json(
                ["--app-data-dir", str(app_dir), "--format", "json", "--", "ALIGN_ONLY_READ_NOISE"]
            )
            self.assertEqual(rc_noise, 0)
            self.assertEqual(d_noise["restored_turns"], 0)

            rc_keep, d_keep = self._run_main_json(
                ["--app-data-dir", str(app_dir), "--format", "json", "--", "ALIGN_CMD_KEEP_TARGET"]
            )
            self.assertEqual(rc_keep, 0)
            self.assertEqual(d_keep["restored_turns"], 1)
            self.assertIn("[run_command]", d_keep["results"][0]["text"])

    def test_sl09_truncated_error_command_reads_transcript_full(self) -> None:
        """SL-09: truncated_fields に content を含むエラー run_command は transcript_full.jsonl を参照する。"""
        with tempfile.TemporaryDirectory() as tmp:
            app_dir = Path(tmp)
            logs_dir = app_dir / "brain" / "conv-full" / ".system_generated" / "logs"
            tp = logs_dir / "transcript.jsonl"
            full_tp = logs_dir / "transcript_full.jsonl"

            short_rows = [
                _make_planner(
                    0,
                    "コマンドを実行します",
                    "2026-11-20T16:00:00Z",
                    tool_calls=[{"name": "run_command", "args": {"CommandLine": "cargo test"}}],
                ),
                _make_generic(
                    1,
                    "Command exited with code 101\nerror: TRUNC_FULL_NEEDLE truncated preview " + ("D" * 60),
                    "2026-11-20T16:00:01Z",
                    status="ERROR",
                    truncated_fields=["content"],
                ),
            ]
            many_lines = "\n".join(f"log line {i:03d}" for i in range(120))
            fake_secret = "SecretTokenValue" + "1234567890"
            full_rows = [
                short_rows[0],
                _make_generic(
                    1,
                    f"HEAD_MARKER_LINE\nerror: TRUNC_FULL_NEEDLE detail\n{many_lines}\nTAIL_MARKER_LINE Bearer {fake_secret}",
                    "2026-11-20T16:00:01Z",
                    status="ERROR",
                ),
            ]
            _write_jsonl(tp, short_rows)
            _write_jsonl(full_tp, full_rows)

            rc, data = self._run_main_json(
                ["--app-data-dir", str(app_dir), "--format", "json", "--", "TRUNC_FULL_NEEDLE"]
            )
            self.assertEqual(rc, 0)
            self.assertEqual(data["restored_turns"], 1)
            body = data["results"][0]["text"]
            self.assertIn("[run_command full]", body)
            self.assertIn("HEAD_MARKER_LINE", body)
            self.assertIn("TAIL_MARKER_LINE", body)
            self.assertIn("行省略", body)
            self.assertIn("[REDACTED]", body)
            self.assertNotIn("SecretTokenValue1234567890", body)

    def test_sl10_include_and_exclude_conversation_id(self) -> None:
        """SL-10: --conversation-id と --exclude-conversation-id の絞り込みが機能する。"""
        with tempfile.TemporaryDirectory() as tmp:
            app_dir = Path(tmp)
            for cid in ("conv-a", "conv-b"):
                tp = app_dir / "brain" / cid / ".system_generated" / "logs" / "transcript.jsonl"
                _write_jsonl(tp, [_make_user(0, f"共通語 FILTER_CID_TOKEN {cid}", "2026-11-20T17:00:00Z")])

            rc_ex, d_ex = self._run_main_json(
                [
                    "--app-data-dir",
                    str(app_dir),
                    "--exclude-conversation-id",
                    "conv-a",
                    "--format",
                    "json",
                    "--",
                    "FILTER_CID_TOKEN",
                ]
            )
            self.assertEqual(rc_ex, 0)
            self.assertEqual([r["conv_id"] for r in d_ex["results"]], ["conv-b"])

            rc_in, d_in = self._run_main_json(
                [
                    "--app-data-dir",
                    str(app_dir),
                    "--conversation-id",
                    "conv-a",
                    "--format",
                    "json",
                    "--",
                    "FILTER_CID_TOKEN",
                ]
            )
            self.assertEqual(rc_in, 0)
            self.assertEqual([r["conv_id"] for r in d_in["results"]], ["conv-a"])

    def test_sl11_fallback_to_python_when_rg_missing(self) -> None:
        """SL-11: shutil.which('rg') が None の場合は Python 走査へ自動フォールバックする。"""
        with tempfile.TemporaryDirectory() as tmp:
            app_dir = Path(tmp)
            tp = app_dir / "brain" / "conv-norg" / ".system_generated" / "logs" / "transcript.jsonl"
            _write_jsonl(tp, [_make_user(0, "FALLBACK_NO_RG_TOKEN", "2026-11-20T18:00:00Z")])

            with mock.patch.object(mod.shutil, "which", return_value=None):
                rc, data = self._run_main_json(
                    ["--app-data-dir", str(app_dir), "--format", "json", "--", "FALLBACK_NO_RG_TOKEN"]
                )
            self.assertEqual(rc, 0)
            self.assertFalse(data["used_rg"])
            self.assertEqual(data["restored_turns"], 1)

    def test_sl12_repo_docs_and_git_log(self) -> None:
        """SL-12: --repo 指定で docs/*.md と git log が検索対象に含まれる。"""
        if not shutil.which("git"):
            self.skipTest("git が見つからない環境のためスキップ")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            app_dir = root / "app"
            (app_dir / "brain").mkdir(parents=True)
            repo = root / "repo"
            (repo / "docs").mkdir(parents=True)
            (repo / "docs" / "design.md").write_text("設計メモ: REPO_DOC_UNIQUE_KEY", encoding="utf-8")

            subprocess.run(["git", "init"], cwd=repo, check=True, capture_output=True)
            subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=repo, check=True, capture_output=True)
            subprocess.run(["git", "config", "user.name", "Tester"], cwd=repo, check=True, capture_output=True)
            subprocess.run(["git", "add", "docs/design.md"], cwd=repo, check=True, capture_output=True)
            subprocess.run(
                ["git", "commit", "-m", "feat: GIT_LOG_UNIQUE_KEY の導入"],
                cwd=repo,
                check=True,
                capture_output=True,
            )

            rc, data = self._run_main_json(
                [
                    "--app-data-dir",
                    str(app_dir),
                    "--repo",
                    str(repo),
                    "--format",
                    "json",
                    "--",
                    "REPO_DOC_UNIQUE_KEY",
                    "GIT_LOG_UNIQUE_KEY",
                ]
            )
            self.assertEqual(rc, 0)
            kinds = {r["source_kind"] for r in data["results"]}
            self.assertIn("repo_doc", kinds)
            self.assertIn("git_commit", kinds)

    def test_sl13_tokenize_and_estimate_tokens(self) -> None:
        """SL-13: tokenize が識別子分割・先頭ハイフン・日本語 2/3-gram を行い estimate_tokens が仕様通り動く。"""
        toks_rust = mod.tokenize("std::io::ErrorKind")
        for expected in ("std::io::errorkind", "std", "io", "error", "kind", "errorkind"):
            self.assertIn(expected, toks_rust)

        toks_flag = mod.tokenize("--min-steps")
        for expected in ("min-steps", "min", "steps"):
            self.assertIn(expected, toks_flag)

        toks_jp = mod.tokenize("却下理由")
        for expected in ("却下", "下理", "理由", "却下理", "下理由"):
            self.assertIn(expected, toks_jp)

        self.assertEqual(mod.tokenize("なぜ"), ["なぜ"])
        self.assertEqual(mod.estimate_tokens("abcd"), 1)
        self.assertEqual(mod.estimate_tokens("あいう"), 2)

    def test_sl14_stats_only_hides_body(self) -> None:
        """SL-14: --stats-only では本文が出力されず統計情報と先頭 ID のみが出力される。"""
        with tempfile.TemporaryDirectory() as tmp:
            app_dir = Path(tmp)
            tp = app_dir / "brain" / "12345678-aaaa-bbbb" / ".system_generated" / "logs" / "transcript.jsonl"
            _write_jsonl(
                tp,
                [_make_user(0, "STATS_NEEDLE SECRET_BODY_SHOULD_NOT_APPEAR", "2026-11-20T19:00:00Z")],
            )
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = mod.main(["--app-data-dir", str(app_dir), "--stats-only", "--", "STATS_NEEDLE"])
            self.assertEqual(rc, 0)
            out = buf.getvalue()
            self.assertIn("12345678", out)
            self.assertIn("経過時間", out)
            self.assertNotIn("SECRET_BODY_SHOULD_NOT_APPEAR", out)

    def test_sl15_short_error_generic_not_dropped(self) -> None:
        """SL-15: 40 文字未満の短いエラー GENERIC も検索対象として保持される。"""
        with tempfile.TemporaryDirectory() as tmp:
            app_dir = Path(tmp)
            tp = app_dir / "brain" / "conv-short-err" / ".system_generated" / "logs" / "transcript.jsonl"
            _write_jsonl(
                tp,
                [
                    _make_planner(
                        0,
                        "テストを実行します",
                        "2026-11-20T10:00:00Z",
                        tool_calls=[{"name": "run_command", "args": {"CommandLine": "pytest"}}],
                    ),
                    _make_generic(1, "FAILED x", "2026-11-20T10:00:01Z", status="ERROR"),
                ],
            )
            rc, data = self._run_main_json(
                ["--app-data-dir", str(app_dir), "--format", "json", "--", "FAILED"]
            )
            self.assertEqual(rc, 0)
            self.assertEqual(data["restored_turns"], 1)
            self.assertIn("FAILED x", data["results"][0]["text"])

    def test_sl16_no_rg_matches_json_escaped_windows_path(self) -> None:
        """SL-16: --no-rg 経路でも JSON エスケープされた Windows パスがヒットする。"""
        with tempfile.TemporaryDirectory() as tmp:
            app_dir = Path(tmp)
            tp = app_dir / "brain" / "conv-winpath" / ".system_generated" / "logs" / "transcript.jsonl"
            _write_jsonl(
                tp,
                [_make_user(0, r"作業パスは C:\Users\meshi\proj です", "2026-11-20T10:00:00Z")],
            )
            rc, data = self._run_main_json(
                ["--app-data-dir", str(app_dir), "--no-rg", "--format", "json", "--", r"C:\Users\meshi\proj"]
            )
            self.assertEqual(rc, 0)
            self.assertFalse(data["used_rg"])
            self.assertEqual(data["restored_turns"], 1)
            self.assertIn(r"C:\Users\meshi\proj", data["results"][0]["text"])

    def test_sl17_excerpt_picks_window_with_most_term_hits(self) -> None:
        """SL-17: 長文内で分割部品のみ頻出する窓より完全一致を含む窓が抜粋に選ばれる。"""
        with tempfile.TemporaryDirectory() as tmp:
            app_dir = Path(tmp)
            tp = app_dir / "brain" / "conv-winpick" / ".system_generated" / "logs" / "transcript.jsonl"
            # 冒頭に完全一致、後方に分離語の大量出現を置く
            head_part = "冒頭の調査結果: std::io::ErrorKind が原因でした。" + ("X" * 1200)
            tail_part = (" std io Error Kind " * 60) + ("Y" * 300)
            _write_jsonl(tp, [_make_planner(0, head_part + tail_part, "2026-11-20T10:00:00Z")])

            rc, data = self._run_main_json(
                [
                    "--app-data-dir",
                    str(app_dir),
                    "--budget-tokens",
                    "250",
                    "--format",
                    "json",
                    "--",
                    "std::io::ErrorKind",
                ]
            )
            self.assertEqual(rc, 0)
            self.assertEqual(data["restored_turns"], 1)
            self.assertIn("std::io::ErrorKind", data["results"][0]["text"])

    def test_sl18_max_turns_caps_primary_hits(self) -> None:
        """SL-18: --max-turns が --max-primary より小さい場合、主ヒットも max_turns 以下に抑えられる。"""
        with tempfile.TemporaryDirectory() as tmp:
            app_dir = Path(tmp)
            for idx in range(5):
                tp = app_dir / "brain" / f"conv-cap-{idx}" / ".system_generated" / "logs" / "transcript.jsonl"
                _write_jsonl(tp, [_make_user(0, f"CAP_NEEDLE_{idx} CAP_COMMON_KEY", f"2026-11-20T10:0{idx}:00Z")])

            rc, data = self._run_main_json(
                [
                    "--app-data-dir",
                    str(app_dir),
                    "--max-primary",
                    "8",
                    "--max-turns",
                    "2",
                    "--format",
                    "json",
                    "--",
                    "CAP_COMMON_KEY",
                ]
            )
            self.assertEqual(rc, 0)
            self.assertLessEqual(data["restored_turns"], 2)
            self.assertLessEqual(len(data["results"]), 2)

    def test_sl19_long_log_many_windows_does_not_crowd_out_other_conv(self) -> None:
        """SL-19: 1 会話の 40 窓以上がヒットしても、別会話の短い一致が主ヒットから押し出されない。"""
        with tempfile.TemporaryDirectory() as tmp:
            app_dir = Path(tmp)
            tp_long = app_dir / "brain" / "conv-long-flood" / ".system_generated" / "logs" / "transcript.jsonl"
            # 40 窓超（672 * 42 文字以上）の全窓に検索語を配置
            flood_chunk = "FLOOD_TERM_ALPHA " + ("a" * 655)
            _write_jsonl(tp_long, [_make_planner(0, flood_chunk * 42, "2026-11-20T10:00:00Z")])

            tp_short = app_dir / "brain" / "conv-short-gem" / ".system_generated" / "logs" / "transcript.jsonl"
            _write_jsonl(tp_short, [_make_planner(0, "短い決定: FLOOD_TERM_ALPHA は却下", "2026-11-20T11:00:00Z")])

            rc, data = self._run_main_json(
                ["--app-data-dir", str(app_dir), "--format", "json", "--", "FLOOD_TERM_ALPHA"]
            )
            self.assertEqual(rc, 0)
            cids = {r["conv_id"] for r in data["results"]}
            self.assertIn("conv-long-flood", cids)
            self.assertIn("conv-short-gem", cids)

    def test_sl20_artifact_keeps_real_conv_id_and_session_link(self) -> None:
        """SL-20: アーティファクト md は実 conv_id を保持し conversation://<実ID> でリンクされる。"""
        with tempfile.TemporaryDirectory() as tmp:
            app_dir = Path(tmp)
            art = app_dir / "brain" / "abc12345-real" / "decision.md"
            art.parent.mkdir(parents=True, exist_ok=True)
            art.write_text("決定記録: ARTIFACT_LINK_NEEDLE", encoding="utf-8")

            rc_j, data = self._run_main_json(
                ["--app-data-dir", str(app_dir), "--format", "json", "--", "ARTIFACT_LINK_NEEDLE"]
            )
            self.assertEqual(rc_j, 0)
            self.assertEqual(data["results"][0]["conv_id"], "abc12345-real")
            self.assertTrue(data["results"][0]["source_key"].startswith("artifact:"))

            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc_m = mod.main(["--app-data-dir", str(app_dir), "--", "ARTIFACT_LINK_NEEDLE"])
            self.assertEqual(rc_m, 0)
            md_out = buf.getvalue()
            self.assertIn("conversation://abc12345-real", md_out)
            self.assertNotIn("conversation://artifact:", md_out)
            self.assertIn("decision.md", md_out)

    def test_sl21_match_line_idx_distinguished_from_turn_first_line(self) -> None:
        """SL-21: L0 の planner と L1 の GENERIC のうち後者だけに一致すると line_idx=0, match_line_idx=1 となる。"""
        with tempfile.TemporaryDirectory() as tmp:
            app_dir = Path(tmp)
            tp = app_dir / "brain" / "conv-matchline" / ".system_generated" / "logs" / "transcript.jsonl"
            _write_jsonl(
                tp,
                [
                    _make_planner(
                        0,
                        "テストを実行します",
                        "2026-11-20T10:00:00Z",
                        tool_calls=[{"name": "run_command", "args": {"CommandLine": "pytest"}}],
                    ),
                    _make_generic(
                        1,
                        "PermissionError: MATCH_LINE_NEEDLE in subprocess execution with details",
                        "2026-11-20T10:00:01Z",
                        status="ERROR",
                    ),
                ],
            )
            rc, data = self._run_main_json(
                ["--app-data-dir", str(app_dir), "--format", "json", "--", "MATCH_LINE_NEEDLE"]
            )
            self.assertEqual(rc, 0)
            res = data["results"][0]
            self.assertEqual(res["line_idx"], 0)
            self.assertEqual(res["match_line_idx"], 1)

            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                mod.main(["--app-data-dir", str(app_dir), "--", "MATCH_LINE_NEEDLE"])
            self.assertIn("match L1", buf.getvalue())

    def test_sl22_full_replacement_keeps_short_when_second_term_omitted(self) -> None:
        """SL-22: 複数語検索で完全版 head/tail に片方の語しかない場合は短縮版も併記される。"""
        with tempfile.TemporaryDirectory() as tmp:
            app_dir = Path(tmp)
            logs_dir = app_dir / "brain" / "conv-full2" / ".system_generated" / "logs"
            tp = logs_dir / "transcript.jsonl"
            full_tp = logs_dir / "transcript_full.jsonl"

            short_rows = [
                _make_planner(
                    0,
                    "テスト実行",
                    "2026-11-20T16:00:00Z",
                    tool_calls=[{"name": "run_command", "args": {"CommandLine": "cargo test"}}],
                ),
                _make_generic(
                    1,
                    "error: TERM_ALPHA_ONLY_HEAD と TERM_BETA_ONLY_SHORT が失敗しました " + ("Z" * 50),
                    "2026-11-20T16:00:01Z",
                    status="ERROR",
                    truncated_fields=["content"],
                ),
            ]
            # 完全版では TERM_BETA_ONLY_SHORT が中略（50行目付近）にだけある
            mid_lines = [f"line {i:03d}" for i in range(120)]
            mid_lines[55] = "TERM_BETA_ONLY_SHORT"
            full_rows = [
                short_rows[0],
                _make_generic(
                    1,
                    "error: TERM_ALPHA_ONLY_HEAD\n" + "\n".join(mid_lines),
                    "2026-11-20T16:00:01Z",
                    status="ERROR",
                ),
            ]
            _write_jsonl(tp, short_rows)
            _write_jsonl(full_tp, full_rows)

            rc, data = self._run_main_json(
                [
                    "--app-data-dir",
                    str(app_dir),
                    "--format",
                    "json",
                    "--",
                    "TERM_ALPHA_ONLY_HEAD",
                    "TERM_BETA_ONLY_SHORT",
                ]
            )
            self.assertEqual(rc, 0)
            body = data["results"][0]["text"]
            self.assertIn("TERM_ALPHA_ONLY_HEAD", body)
            self.assertIn("TERM_BETA_ONLY_SHORT", body)
            self.assertIn("[run_command full]", body)

    def test_sl23_budget_shrinks_excerpt_radius_to_fit_100_tokens(self) -> None:
        """SL-23: --budget-tokens 100 で長い日本語ログを検索すると半径縮小により予算内に収まる。"""
        with tempfile.TemporaryDirectory() as tmp:
            app_dir = Path(tmp)
            tp = app_dir / "brain" / "conv-tight" / ".system_generated" / "logs" / "transcript.jsonl"
            long_jp = ("あ" * 600) + "却下の理由" + ("い" * 600)
            _write_jsonl(tp, [_make_planner(0, long_jp, "2026-11-20T10:00:00Z")])

            rc, data = self._run_main_json(
                [
                    "--app-data-dir",
                    str(app_dir),
                    "--budget-tokens",
                    "100",
                    "--format",
                    "json",
                    "--",
                    "却下",
                ]
            )
            self.assertEqual(rc, 0)
            self.assertTrue(data["fallback"])
            self.assertLessEqual(data["estimated_tokens"], 100)
            self.assertIn("却下", data["results"][0]["text"])

    def test_sl24_utc_sort_key_normalizes_timezone_offsets(self) -> None:
        """SL-24: 時差付きコミットと Z 時刻の transcript が UTC 基準の正しい時系列で並ぶ。"""
        self.assertLess(
            mod._utc_sort_key("2026-11-01T00:30:00+09:00"),
            mod._utc_sort_key("2026-10-31T22:00:00Z"),
        )
        self.assertEqual(mod._utc_sort_key(""), "9999-12-31T23:59:59.999999Z")

        if not shutil.which("git"):
            self.skipTest("git が見つからない環境のためスキップ")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            app_dir = root / "app"
            tp = app_dir / "brain" / "conv-tz" / ".system_generated" / "logs" / "transcript.jsonl"
            _write_jsonl(tp, [_make_user(0, "TZ_ORDER_NEEDLE transcript", "2026-10-31T22:00:00Z")])

            repo = root / "repo"
            repo.mkdir(parents=True)
            (repo / "a.txt").write_text("x", encoding="utf-8")
            env = os.environ.copy()
            env["GIT_COMMITTER_DATE"] = "2026-11-01T00:30:00+09:00"
            env["GIT_AUTHOR_DATE"] = "2026-11-01T00:30:00+09:00"
            subprocess.run(["git", "init"], cwd=repo, check=True, capture_output=True)
            subprocess.run(["git", "config", "user.email", "t@example.com"], cwd=repo, check=True, capture_output=True)
            subprocess.run(["git", "config", "user.name", "Tester"], cwd=repo, check=True, capture_output=True)
            subprocess.run(["git", "add", "a.txt"], cwd=repo, check=True, capture_output=True)
            subprocess.run(
                ["git", "commit", "-m", "TZ_ORDER_NEEDLE commit"],
                cwd=repo,
                env=env,
                check=True,
                capture_output=True,
            )

            rc, data = self._run_main_json(
                [
                    "--app-data-dir",
                    str(app_dir),
                    "--repo",
                    str(repo),
                    "--format",
                    "json",
                    "--",
                    "TZ_ORDER_NEEDLE",
                ]
            )
            self.assertEqual(rc, 0)
            self.assertEqual(
                [r["source_kind"] for r in data["results"]],
                ["git_commit", "USER_INPUT"],
            )

    def test_sl25_git_commit_subject_secret_masked_in_heading(self) -> None:
        """SL-25: git コミット件名に含まれる秘密トークンが見出し出力でもマスクされる。"""
        if not shutil.which("git"):
            self.skipTest("git が見つからない環境のためスキップ")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            app_dir = root / "app"
            (app_dir / "brain").mkdir(parents=True)
            repo = root / "repo"
            repo.mkdir(parents=True)
            (repo / "a.txt").write_text("x", encoding="utf-8")
            fake_ghp = "ghp_" + ("X" * 30)
            subprocess.run(["git", "init"], cwd=repo, check=True, capture_output=True)
            subprocess.run(["git", "config", "user.email", "t@example.com"], cwd=repo, check=True, capture_output=True)
            subprocess.run(["git", "config", "user.name", "Tester"], cwd=repo, check=True, capture_output=True)
            subprocess.run(["git", "add", "a.txt"], cwd=repo, check=True, capture_output=True)
            subprocess.run(
                ["git", "commit", "-m", f"COMMIT_SECRET_KEY {fake_ghp}"],
                cwd=repo,
                check=True,
                capture_output=True,
            )

            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = mod.main(
                    ["--app-data-dir", str(app_dir), "--repo", str(repo), "--", "COMMIT_SECRET_KEY"]
                )
            self.assertEqual(rc, 0)
            out = buf.getvalue()
            self.assertIn("[REDACTED]", out)
            self.assertNotIn("ghp_", out)

    def test_sl26_tool_arg_masked_before_200char_truncation(self) -> None:
        """SL-26: ツール引数の切り詰め位置をまたぐ秘密トークンも切断前にマスクされる。"""
        with tempfile.TemporaryDirectory() as tmp:
            app_dir = Path(tmp)
            tp = app_dir / "brain" / "conv-toolmask" / ".system_generated" / "logs" / "transcript.jsonl"
            fake_ghp = "ghp_" + ("A" * 30)
            cmd = ("x" * 190) + fake_ghp
            _write_jsonl(
                tp,
                [
                    _make_planner(
                        0,
                        "TOOL_ARG_MASK_QUERY の実行記録",
                        "2026-11-20T10:00:00Z",
                        tool_calls=[{"name": "run_command", "args": {"CommandLine": cmd}}],
                    )
                ],
            )
            rc, data = self._run_main_json(
                ["--app-data-dir", str(app_dir), "--format", "json", "--", "TOOL_ARG_MASK_QUERY"]
            )
            self.assertEqual(rc, 0)
            text = data["results"][0]["text"]
            self.assertIn("[REDACTED]", text)
            self.assertNotIn("ghp_", text)
            self.assertNotIn("AAAAAAAA", text)

    def test_sl27_query_terms_masked_in_markdown_json_and_stats_only(self) -> None:
        """SL-27: 検索語に含まれる URL 認証情報が 0 件時・stats-only を含む全出力形式でマスクされる。"""
        with tempfile.TemporaryDirectory() as tmp:
            app_dir = Path(tmp)
            (app_dir / "brain").mkdir(parents=True)
            cred_url = "https://user:pass123@example.com"

            buf_md = io.StringIO()
            with contextlib.redirect_stdout(buf_md):
                rc1 = mod.main(["--app-data-dir", str(app_dir), "--", cred_url])
            self.assertEqual(rc1, 0)
            self.assertNotIn("pass123", buf_md.getvalue())
            self.assertIn("[REDACTED]", buf_md.getvalue())

            rc2, data_json = self._run_main_json(
                ["--app-data-dir", str(app_dir), "--format", "json", "--stats-only", "--", cred_url]
            )
            self.assertEqual(rc2, 0)
            self.assertNotIn("pass123", json.dumps(data_json, ensure_ascii=False))
            self.assertIn("[REDACTED]", data_json["terms"][0])

    def test_sl28_budget_reclaims_margin_from_shrinkable_excerpt(self) -> None:
        """SL-28: 一方の抜粋が最小半径でも他方を縮めれば予算内に収まる場合は警告なしで収める。"""
        with tempfile.TemporaryDirectory() as tmp:
            app_dir = Path(tmp)
            tp1 = app_dir / "brain" / "conv-jp-tight" / ".system_generated" / "logs" / "transcript.jsonl"
            _write_jsonl(
                tp1,
                [_make_planner(0, ("あ" * 300) + "RECLAIM_KEY" + ("い" * 300), "2026-11-20T10:00:00Z")],
            )
            tp2 = app_dir / "brain" / "conv-en-shrink" / ".system_generated" / "logs" / "transcript.jsonl"
            _write_jsonl(
                tp2,
                [_make_planner(0, ("A" * 180) + "RECLAIM_KEY" + ("B" * 180), "2026-11-20T10:01:00Z")],
            )

            rc, data = self._run_main_json(
                [
                    "--app-data-dir",
                    str(app_dir),
                    "--budget-tokens",
                    "105",
                    "--format",
                    "json",
                    "--",
                    "RECLAIM_KEY",
                ]
            )
            self.assertEqual(rc, 0)
            self.assertEqual(data["restored_turns"], 2)
            self.assertLessEqual(data["estimated_tokens"], 105)
            self.assertEqual(data["warnings"], [])

    def test_sl29_excerpt_preserves_full_matched_path_and_warns_when_match_exceeds_budget(self) -> None:
        """SL-29: 一致範囲を外側から縮めて長いパス全体を保持し、一致自体が予算超のときは警告する。"""
        long_path = "C:/workspace/" + ("segment_dir/" * 6) + "target_file_name.py"
        self.assertGreaterEqual(len(long_path), 95)

        # (a) 一致全体を残せる場合: 99 文字級パス 2 件を budget 155 で検索しても両方パス全体が残る
        with tempfile.TemporaryDirectory() as tmp:
            app_dir = Path(tmp)
            for idx in range(2):
                tp = app_dir / "brain" / f"conv-path-{idx}" / ".system_generated" / "logs" / "transcript.jsonl"
                body = ("診断メッセージの文脈" * 12) + " " + long_path + " " + ("後続の補足説明" * 12)
                _write_jsonl(tp, [_make_planner(0, body, f"2026-11-20T10:0{idx}:00Z")])

            rc, data = self._run_main_json(
                [
                    "--app-data-dir",
                    str(app_dir),
                    "--budget-tokens",
                    "155",
                    "--format",
                    "json",
                    "--",
                    long_path,
                ]
            )
            self.assertEqual(rc, 0)
            self.assertEqual(data["restored_turns"], 2)
            self.assertLessEqual(data["estimated_tokens"], 155)
            for res in data["results"]:
                self.assertIn(long_path, res["text"])

        # (b) 一致自体が予算より長い場合: 一致を途中で切らず警告付きで出力する
        huge_token = "VERY_LONG_IDENTIFIER_" + ("X" * 500)
        with tempfile.TemporaryDirectory() as tmp:
            app_dir = Path(tmp)
            tp = app_dir / "brain" / "conv-huge" / ".system_generated" / "logs" / "transcript.jsonl"
            _write_jsonl(
                tp,
                [_make_planner(0, ("前置き" * 30) + " " + huge_token + " " + ("後書き" * 30), "2026-11-20T10:00:00Z")],
            )
            rc2, data2 = self._run_main_json(
                [
                    "--app-data-dir",
                    str(app_dir),
                    "--budget-tokens",
                    "100",
                    "--format",
                    "json",
                    "--",
                    huge_token,
                ]
            )
            self.assertEqual(rc2, 0)
            self.assertIn(huge_token, data2["results"][0]["text"])
            self.assertTrue(data2["warnings"])

    def test_sl30_unicode_casefold_span_mapping(self) -> None:
        """SL-30: casefold で長さが変わる Unicode 語 (Straße) とその後続語が正しい元位置で抜粋される。"""
        with tempfile.TemporaryDirectory() as tmp:
            app_dir = Path(tmp)
            tp = app_dir / "brain" / "conv-sz" / ".system_generated" / "logs" / "transcript.jsonl"
            content = "Start Straße " + ("長い診断文が続きます。" * 40) + " TAIL_AFTER_SZ " + ("末尾" * 30)
            _write_jsonl(tp, [_make_planner(0, content, "2026-11-20T10:00:00Z")])

            rc1, d1 = self._run_main_json(
                [
                    "--app-data-dir",
                    str(app_dir),
                    "--budget-tokens",
                    "100",
                    "--format",
                    "json",
                    "--",
                    "Straße",
                ]
            )
            self.assertEqual(rc1, 0)
            self.assertIn("Straße", d1["results"][0]["text"])

            rc2, d2 = self._run_main_json(
                [
                    "--app-data-dir",
                    str(app_dir),
                    "--budget-tokens",
                    "100",
                    "--format",
                    "json",
                    "--",
                    "TAIL_AFTER_SZ",
                ]
            )
            self.assertEqual(rc2, 0)
            self.assertIn("TAIL_AFTER_SZ", d2["results"][0]["text"])

    def test_sl31_term_order_independent_longest_span_at_same_start(self) -> None:
        """SL-31: 接頭辞と完全パスの両順序で検索しても同じ開始位置では長い完全パス全体が保持される。"""
        prefix = "C:/workspace/"
        full_path = prefix + ("segment_dir/" * 6) + "target_file_name.py"
        with tempfile.TemporaryDirectory() as tmp:
            app_dir = Path(tmp)
            for idx in range(2):
                tp = app_dir / "brain" / f"conv-order-{idx}" / ".system_generated" / "logs" / "transcript.jsonl"
                body = ("診断メッセージの文脈" * 12) + " " + full_path + " " + ("補足" * 12)
                _write_jsonl(tp, [_make_planner(0, body, f"2026-11-20T10:0{idx}:00Z")])

            for ordered_terms in ([prefix, full_path], [full_path, prefix]):
                rc, data = self._run_main_json(
                    [
                        "--app-data-dir",
                        str(app_dir),
                        "--budget-tokens",
                        "100",
                        "--format",
                        "json",
                        "--",
                        *ordered_terms,
                    ]
                )
                self.assertEqual(rc, 0)
                self.assertEqual(data["restored_turns"], 2)
                for res in data["results"]:
                    self.assertIn(full_path, res["text"])

    def test_sl32_cross_window_match_and_masked_match_never_produce_ellipsis_only(self) -> None:
        """SL-32: 窓境界をまたぐ長いパスも省略記号だけにならず保持され、マスク後消失時も本文が残る。"""
        long_path = "C:/cross_boundary/" + ("nested_directory/" * 5) + "final_module.py"
        self.assertGreater(len(long_path), 100)
        with tempfile.TemporaryDirectory() as tmp:
            app_dir = Path(tmp)
            for idx in range(8):
                tp = app_dir / "brain" / f"conv-cross-{idx}" / ".system_generated" / "logs" / "transcript.jsonl"
                # 768 文字窓境界を必ずまたぐ 700 文字目付近に長いパスを配置
                body = ("あ" * 700) + " " + long_path + " " + ("い" * 200)
                _write_jsonl(tp, [_make_planner(0, body, f"2026-11-20T10:0{idx}:00Z")])

            rc, data = self._run_main_json(
                [
                    "--app-data-dir",
                    str(app_dir),
                    "--budget-tokens",
                    "100",
                    "--format",
                    "json",
                    "--",
                    long_path,
                ]
            )
            self.assertEqual(rc, 0)
            self.assertEqual(data["restored_turns"], 8)
            for res in data["results"]:
                self.assertIn(long_path, res["text"])
                self.assertNotEqual(res["text"].strip("."), "")

            # マスクで検索語が [REDACTED] に置換された場合でも空抜粋にならないこと
            fake_ghp = "ghp_" + ("Z" * 30)
            tp_mask = app_dir / "brain" / "conv-masked-only" / ".system_generated" / "logs" / "transcript.jsonl"
            _write_jsonl(
                tp_mask,
                [_make_planner(0, ("文脈" * 120) + f" token={fake_ghp} " + ("続き" * 120), "2026-11-21T10:00:00Z")],
            )
            rc_m, data_m = self._run_main_json(
                [
                    "--app-data-dir",
                    str(app_dir),
                    "--conversation-id",
                    "conv-masked-only",
                    "--budget-tokens",
                    "100",
                    "--format",
                    "json",
                    "--",
                    fake_ghp,
                ]
            )
            self.assertEqual(rc_m, 0)
            self.assertEqual(data_m["restored_turns"], 1)
            self.assertNotIn(fake_ghp, data_m["results"][0]["text"])
            self.assertNotEqual(data_m["results"][0]["text"].strip("."), "")


if __name__ == "__main__":
    unittest.main()
