#!/usr/bin/env python3
"""audit_context_metrics.py のユニットテスト（SCA-01〜SCA-18）。"""

from __future__ import annotations

import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
import urllib.error

_THIS_DIR = Path(__file__).resolve().parent
if str(_THIS_DIR) not in sys.path:
    sys.path.insert(0, str(_THIS_DIR))

import audit_context_metrics as mod  # noqa: E402


class _FakeHttpResponse:
    """urllib.request.urlopen 互換の最小モック応答。"""

    def __init__(self, body: dict) -> None:
        self._raw = json.dumps(body, ensure_ascii=False).encode("utf-8")

    def read(self) -> bytes:
        return self._raw

    def __enter__(self) -> _FakeHttpResponse:
        return self

    def __exit__(self, *args: object) -> None:
        return None


def _write_session(
    app_dir: Path,
    cid: str,
    steps: list[dict | str],
    *,
    full_steps: list[dict | str] | None = None,
    subagent_ids: list[str] | None = None,
    subagent_types: dict[str, str] | None = None,
) -> Path:
    conv_dir = app_dir / "brain" / cid
    logs_dir = conv_dir / ".system_generated" / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    t_path = logs_dir / "transcript.jsonl"
    lines = [s if isinstance(s, str) else json.dumps(s, ensure_ascii=False) for s in steps]
    t_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    if full_steps is not None:
        f_path = logs_dir / "transcript_full.jsonl"
        f_lines = [s if isinstance(s, str) else json.dumps(s, ensure_ascii=False) for s in full_steps]
        f_path.write_text("\n".join(f_lines) + "\n", encoding="utf-8")

    if subagent_ids:
        sub_dir = conv_dir / ".system_generated" / "subagents"
        sub_dir.mkdir(parents=True, exist_ok=True)
        for sub_id in subagent_ids:
            payload: dict = {"conversationId": sub_id}
            if subagent_types and sub_id in subagent_types:
                payload["subagentDescriptor"] = {"typeName": subagent_types[sub_id]}
            (sub_dir / f"{sub_id}.json").write_text(
                json.dumps(payload), encoding="utf-8"
            )
    return t_path


def _user_step(idx: int, text: str, ts: str = "2026-11-20T01:00:00Z") -> dict:
    return {
        "step_index": idx,
        "source": "USER_EXPLICIT",
        "type": "USER_INPUT",
        "status": "DONE",
        "created_at": ts,
        "content": f"<USER_REQUEST>\n{text}\n</USER_REQUEST>",
    }


def _planner_step(
    idx: int,
    *,
    ts: str = "2026-11-20T01:00:10Z",
    model: str = "gemini-4-neon-high",
    inp: int | None = 1000,
    cac: int | None = 3000,
    out: int | None = 100,
    tool_calls: list[dict] | None = None,
    content: str = "",
    thinking: str = "",
) -> dict:
    row: dict = {
        "step_index": idx,
        "source": "MODEL",
        "type": "PLANNER_RESPONSE",
        "status": "DONE",
        "created_at": ts,
        "model": model,
    }
    if inp is not None:
        row["input_tokens"] = inp
    if cac is not None:
        row["cache_read_tokens"] = cac
    if out is not None:
        row["output_tokens"] = out
    if tool_calls is not None:
        row["tool_calls"] = tool_calls
    if content:
        row["content"] = content
    if thinking:
        row["thinking"] = thinking
    return row


def _generic_step(
    idx: int,
    content: str,
    *,
    ts: str = "2026-11-20T01:00:11Z",
    status: str = "DONE",
    error: str = "",
    truncated_fields: list[str] | None = None,
) -> dict:
    row: dict = {
        "step_index": idx,
        "source": "MODEL",
        "type": "GENERIC",
        "status": status,
        "created_at": ts,
        "content": content,
    }
    if error:
        row["error"] = error
    if truncated_fields is not None:
        row["truncated_fields"] = truncated_fields
    return row


class TestAuditContextMetrics(unittest.TestCase):
    """SCA-01〜SCA-18 の仕様検証テスト。"""

    def test_SCA_01_token_and_cache_calculation_and_zero_div(self) -> None:
        """SCA-01: 初回編集前トークン、ピークコンテキスト、キャッシュヒット率とゼロ除算回避を検証する。"""
        with tempfile.TemporaryDirectory() as tmp:
            app_dir = Path(tmp)
            t1 = _write_session(
                app_dir,
                "11111111-1111-1111-1111-111111111111",
                [
                    _user_step(0, "バグ修正してください", ts="2026-11-20T01:00:00Z"),
                    _planner_step(
                        1,
                        ts="2026-11-20T01:00:05Z",
                        inp=2000,
                        cac=6000,
                        out=100,
                        tool_calls=[{"name": "read_file", "args": {"Path": '"a.py"'}}],
                    ),
                    _generic_step(2, "Showing lines 1-50 of 50\ncode"),
                    _planner_step(
                        3,
                        ts="2026-11-20T01:00:25Z",
                        inp=1000,
                        cac=9000,
                        out=120,
                        tool_calls=[{"name": "edit_file", "args": {"Path": '"a.py"'}}],
                    ),
                    _generic_step(4, "Edited"),
                    _planner_step(5, ts="2026-11-20T01:00:35Z", inp=500, cac=11500, out=80, content="完了"),
                ],
            )
            m = mod.analyze_session("11111111-1111-1111-1111-111111111111", t1, is_subagent=False)
            self.assertEqual(m.pre_edit_context_tokens, 10000)
            self.assertEqual(m.pre_edit_new_input_tokens, 3000)
            self.assertEqual(m.peak_context_tokens, 12000)
            self.assertEqual(m.turns_to_first_edit, 2)
            self.assertAlmostEqual(m.seconds_to_first_edit or 0.0, 25.0)
            self.assertAlmostEqual(m.cache_hit_rate or 0.0, (6000 + 9000 + 11500) / (3500 + 26500))

            t_zero = _write_session(
                app_dir,
                "22222222-2222-2222-2222-222222222222",
                [_user_step(0, "空トークン"), _planner_step(1, inp=0, cac=0, out=0)],
            )
            mz = mod.analyze_session("22222222-2222-2222-2222-222222222222", t_zero, is_subagent=False)
            self.assertIsNone(mz.cache_hit_rate)
            self.assertEqual(mz.peak_context_tokens, 0)

    def test_SCA_02_five_class_tree_scope_and_session_id_priority(self) -> None:
        """SCA-02: セッション 5 分類、--scope 絞り込み、および --session-id 優先適用を検証する。"""
        with tempfile.TemporaryDirectory() as tmp:
            app_dir = Path(tmp)
            _write_session(
                app_dir,
                "parent-1",
                [_user_step(0, "parent"), _planner_step(1, content="ok")],
                subagent_ids=["sub-1"],
            )
            _write_session(
                app_dir,
                "swarm-coord-1",
                [
                    _user_step(0, "coord"),
                    _planner_step(1, tool_calls=[{"name": "read_board", "args": {}}]),
                    _generic_step(2, "board"),
                ],
                subagent_ids=["worker-1"],
            )
            _write_session(app_dir, "sub-1", [_planner_step(0, content="sub")])
            _write_session(
                app_dir,
                "worker-1",
                [
                    _planner_step(0, tool_calls=[{"name": "post_message", "args": {}}]),
                    _generic_step(1, "posted"),
                ],
            )
            _write_session(app_dir, "orphan-1", [_planner_step(0, content="orphan")])

            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = mod.main(["--app-data-dir", str(app_dir), "--scope", "parent", "--format", "json"])
            self.assertEqual(rc, 0)
            rep = json.loads(buf.getvalue())
            self.assertEqual(
                rep["meta"]["class_counts"],
                {"parent": 1, "swarm_coordinator": 1, "subagent": 1, "swarm_worker": 1, "orphan_or_empty": 1},
            )
            self.assertEqual(rep["meta"]["included_sessions"], 2)

            buf_sub = io.StringIO()
            with contextlib.redirect_stdout(buf_sub):
                rc_sub = mod.main(["--app-data-dir", str(app_dir), "--scope", "subagent", "--format", "json"])
            self.assertEqual(rc_sub, 0)
            self.assertEqual(json.loads(buf_sub.getvalue())["meta"]["included_sessions"], 2)

            # --session-id は --scope parent や --only-with-edits より優先する
            buf_sid = io.StringIO()
            with contextlib.redirect_stdout(buf_sid):
                rc_sid = mod.main(
                    [
                        "--app-data-dir",
                        str(app_dir),
                        "--scope",
                        "parent",
                        "--only-with-edits",
                        "--session-id",
                        "worker-1",
                        "--format",
                        "json",
                    ]
                )
            self.assertEqual(rc_sid, 0)
            rep_sid = json.loads(buf_sid.getvalue())
            self.assertEqual(rep_sid["meta"]["included_sessions"], 1)

    def test_SCA_03_json_args_classification_priority_and_oversized(self) -> None:
        """SCA-03: read_file 引数解析とコード、ロック、免除ファイルの大規模読込分類を検証する。"""
        with tempfile.TemporaryDirectory() as tmp:
            app_dir = Path(tmp)
            t = _write_session(
                app_dir,
                "sess-read",
                [
                    _user_step(0, "確認"),
                    _planner_step(
                        1,
                        tool_calls=[
                            {"name": "read_file", "args": {"Path": '"src/app.py"'}},
                            {"name": "read_file", "args": {"Path": '"src/app.py"', "StartLine": '"1"', "EndLine": '"250"'}},
                            {"name": "read_file", "args": {"Path": '"package-lock.json"'}},
                            {"name": "read_file", "args": {"Path": '"docs/spec.md"'}},
                            {"name": "read_file", "args": {"Path": '"src/small.py"'}},
                        ],
                    ),
                    _generic_step(2, "Showing lines 1-300 of 300\ncode"),
                    _generic_step(3, "Showing lines 1-250 of 300\ncode"),
                    _generic_step(4, "Showing lines 1-500 of 500\nlock"),
                    _generic_step(5, "Showing lines 1-400 of 400\nmd"),
                    _generic_step(6, "Showing lines 1-50 of 50\nsmall"),
                ],
            )
            m = mod.analyze_session("sess-read", t, is_subagent=False)
            self.assertEqual(m.large_code_reads, 2)
            self.assertEqual(m.blind_large_code_reads, 1)
            self.assertEqual(m.oversized_range_reads, 1)
            self.assertEqual(m.large_lock_reads, 1)
            self.assertEqual(m.blind_large_lock_reads, 1)
            self.assertEqual(m.large_exempt_reads, 1)
            self.assertEqual(m.blind_large_exempt_reads, 1)

    def test_SCA_04_redundant_reread_vs_forward_chunking_and_windows_path(self) -> None:
        """SCA-04: 順方向分割や編集後再読を除外し、Windows パス正規化込みで重複再読のみ計上する。"""
        with tempfile.TemporaryDirectory() as tmp:
            app_dir = Path(tmp)
            # 順方向 200 行分割および非重複の前方ジャンプは 0
            t_ok = _write_session(
                app_dir,
                "chunk-ok",
                [
                    _user_step(0, "分割読込と非重複ジャンプ"),
                    _planner_step(1, tool_calls=[{"name": "read_file", "args": {"Path": '"C:\\Repo\\Main.py"', "StartLine": '"1"', "EndLine": '"200"'}}]),
                    _generic_step(2, "Showing lines 1-200 of 600"),
                    _planner_step(3, tool_calls=[{"name": "read_file", "args": {"Path": '"c:/repo/main.py"', "StartLine": '"201"', "EndLine": '"400"'}}]),
                    _generic_step(4, "Showing lines 201-400 of 600"),
                    _planner_step(5, tool_calls=[{"name": "read_file", "args": {"Path": '"c:\\repo\\main.py"', "StartLine": '"401"', "EndLine": '"600"'}}]),
                    _generic_step(6, "Showing lines 401-600 of 600"),
                ],
            )
            m_ok = mod.analyze_session("chunk-ok", t_ok, is_subagent=False)
            self.assertEqual(m_ok.redundant_rereads, 0)

            t_jump = _write_session(
                app_dir,
                "chunk-jump",
                [
                    _user_step(0, "非重複前方ジャンプ"),
                    _planner_step(1, tool_calls=[{"name": "read_file", "args": {"Path": '"C:\\Repo\\Main.py"', "StartLine": '"201"', "EndLine": '"300"'}}]),
                    _generic_step(2, "Showing lines 201-300 of 600"),
                    _planner_step(3, tool_calls=[{"name": "read_file", "args": {"Path": '"c:/repo/main.py"', "StartLine": '"50"', "EndLine": '"120"'}}]),
                    _generic_step(4, "Showing lines 50-120 of 600"),
                ],
            )
            m_jump = mod.analyze_session("chunk-jump", t_jump, is_subagent=False)
            self.assertEqual(m_jump.redundant_rereads, 0)

            # 実質重複範囲の再読は redundant_rereads に計上（Windows パス正規化含む）
            t_overlap = _write_session(
                app_dir,
                "chunk-overlap",
                [
                    _user_step(0, "実質重複読込"),
                    _planner_step(1, tool_calls=[{"name": "read_file", "args": {"Path": '"C:\\Repo\\Main.py"', "StartLine": '"1"', "EndLine": '"200"'}}]),
                    _generic_step(2, "Showing lines 1-200 of 600"),
                    _planner_step(3, tool_calls=[{"name": "read_file", "args": {"Path": '"c:/repo/main.py"', "StartLine": '"150"', "EndLine": '"250"'}}]),
                    _generic_step(4, "Showing lines 150-250 of 600"),
                ],
            )
            m_overlap = mod.analyze_session("chunk-overlap", t_overlap, is_subagent=False)
            self.assertEqual(m_overlap.redundant_rereads, 1)

            # edit_file / write_file 成功後の同一範囲再読は 0、edit_file 失敗後はリセットせず 1
            t_edit = _write_session(
                app_dir,
                "chunk-edit-reset",
                [
                    _user_step(0, "編集後リセット検証"),
                    _planner_step(1, tool_calls=[{"name": "read_file", "args": {"Path": '"C:\\Repo\\Main.py"', "StartLine": '"1"', "EndLine": '"100"'}}]),
                    _generic_step(2, "Showing lines 1-100 of 300"),
                    _planner_step(3, tool_calls=[{"name": "edit_file", "args": {"Path": '"c:/repo/main.py"'}}]),
                    _generic_step(4, "ok", status="DONE"),
                    _planner_step(5, tool_calls=[{"name": "read_file", "args": {"Path": '"c:\\repo\\main.py"', "StartLine": '"1"', "EndLine": '"100"'}}]),
                    _generic_step(6, "Showing lines 1-100 of 300"),
                    _planner_step(7, tool_calls=[{"name": "write_file", "args": {"Path": '"C:\\Repo\\Main.py"'}}]),
                    _generic_step(8, "ok", status="DONE"),
                    _planner_step(9, tool_calls=[{"name": "read_file", "args": {"Path": '"c:/repo/main.py"', "StartLine": '"1"', "EndLine": '"100"'}}]),
                    _generic_step(10, "Showing lines 1-100 of 300"),
                    _planner_step(11, tool_calls=[{"name": "edit_file", "args": {"Path": '"c:/repo/main.py"'}}]),
                    _generic_step(12, "target not found", status="ERROR", error="mismatch"),
                    _planner_step(13, tool_calls=[{"name": "read_file", "args": {"Path": '"c:/repo/main.py"', "StartLine": '"1"', "EndLine": '"100"'}}]),
                    _generic_step(14, "Showing lines 1-100 of 300"),
                ],
            )
            m_edit = mod.analyze_session("chunk-edit-reset", t_edit, is_subagent=False)
            self.assertEqual(m_edit.redundant_rereads, 1)

    def test_SCA_05_parallel_burst_search_before_read_and_pipe_violation(self) -> None:
        """SCA-05: 検索先行率、並列読込バースト、およびパイプ切り詰め違反の検出と非誤検知を検証する。"""
        with tempfile.TemporaryDirectory() as tmp:
            app_dir = Path(tmp)
            t = _write_session(
                app_dir,
                "burst-sess",
                [
                    _user_step(0, "検索と並列"),
                    _planner_step(
                        1,
                        tool_calls=[
                            {"name": "run_command", "args": {"CommandLine": '"rg -n foo src/"'}},
                            {"name": "read_file", "args": {"Path": '"a.py"'}},
                            {"name": "read_file", "args": {"Path": '"b.py"'}},
                            {"name": "read_file", "args": {"Path": '"c.py"'}},
                            {"name": "read_file", "args": {"Path": '"d.py"'}},
                        ],
                    ),
                    _generic_step(2, "hit"),
                    _generic_step(3, "Showing lines 1-10 of 10"),
                    _generic_step(4, "Showing lines 1-10 of 10"),
                    _generic_step(5, "Showing lines 1-10 of 10"),
                    _generic_step(6, "Showing lines 1-10 of 10"),
                    _planner_step(
                        7,
                        tool_calls=[
                            {"name": "run_command", "args": {"CommandLine": '"git diff | Select-Object -First 60"'}},
                            {"name": "run_command", "args": {"CommandLine": '"cat target/head_notes.txt"'}},
                        ],
                    ),
                    _generic_step(8, "Command exited with code 1\npartial"),
                    _generic_step(9, "ok"),
                ],
            )
            m = mod.analyze_session("burst-sess", t, is_subagent=False)
            self.assertTrue(m.search_before_read)
            self.assertEqual(m.parallel_read_burst_turns, 1)
            self.assertEqual(m.pipe_truncate_violations, 1)
            self.assertEqual(m.pipe_truncate_errors, 1)

            # target/head_notes.txt だけを打った場合は検索先行やパイプ違反に誤検出しない
            self.assertFalse(bool(mod.SEARCH_CMD_RE.search("cat target/rg_cache.txt")))
            self.assertFalse(bool(mod.PIPE_TRUNCATE_RE.search("cat target/head_notes.txt")))

    def test_SCA_06_full_lookup_fallback_unpaired_and_malformed_json(self) -> None:
        """SCA-06: transcript_full.jsonl 遅延参照、不在時フォールバック、破損 JSON 行耐性を検証する。"""
        with tempfile.TemporaryDirectory() as tmp:
            app_dir = Path(tmp)
            big_text = "x" * 11_000
            t = _write_session(
                app_dir,
                "full-sess",
                [
                    _user_step(0, "大出力確認"),
                    "BROKEN_JSON_LINE {",
                    _planner_step(
                        2,
                        tool_calls=[
                            {"name": "run_command", "args": {"CommandLine": '"rg foo"'}},
                            {"name": "read_file", "args": {"Path": '"missing_resp.py"'}},
                        ],
                    ),
                    _generic_step(3, "short", truncated_fields=["content"]),
                    # 2 つ目のツール応答が欠落し、いきなり次の PLANNER_RESPONSE が来るケース
                    _planner_step(4, content="done"),
                ],
                full_steps=[
                    _user_step(0, "大出力確認"),
                    "BROKEN_JSON_LINE {",
                    _planner_step(2),
                    _generic_step(3, big_text),
                    _planner_step(4, content="done"),
                ],
            )
            m = mod.analyze_session("full-sess", t, is_subagent=False, lookup_full=True)
            self.assertEqual(m.malformed_lines, 1)
            self.assertEqual(m.unpaired_tool_calls, 1)
            self.assertEqual(m.large_cmd_outputs, 1)
            self.assertEqual(m.full_lookup_misses, 0)

            # --no-full-lookup 時は transcript.jsonl 側のサイズだけ見る
            m_fast = mod.analyze_session("full-sess", t, is_subagent=False, lookup_full=False)
            self.assertEqual(m_fast.large_cmd_outputs, 0)

            # transcript_full.jsonl 不在時はフォールバックし full_lookup_misses に計上
            t.with_name("transcript_full.jsonl").unlink()
            m_miss = mod.analyze_session("full-sess", t, is_subagent=False, lookup_full=True)
            self.assertEqual(m_miss.large_cmd_outputs, 0)
            self.assertEqual(m_miss.full_lookup_misses, 1)

    def test_SCA_07_cutoff_spanning_since_until_low_sample_and_zero_delta(self) -> None:
        """SCA-07: --cutoff 境界帰属、期間フィルタ、[low-n] 判定、およびゼロ基準変化率を検証する。"""
        with tempfile.TemporaryDirectory() as tmp:
            app_dir = Path(tmp)
            # Before (1 件、カットオフ跨ぎ)
            _write_session(
                app_dir,
                "before-span",
                [
                    _user_step(0, "span", ts="2026-11-21T10:00:00Z"),
                    _planner_step(1, ts="2026-11-21T10:20:00Z", model="model-a", inp=100, cac=0, content="end"),
                ],
            )
            # After (境界時刻ちょうど == cutoff は After 帰属)
            _write_session(
                app_dir,
                "after-exact",
                [
                    _user_step(0, "after", ts="2026-11-21T10:13:36Z"),
                    _planner_step(1, ts="2026-11-21T10:15:00Z", model="model-a", inp=200, cac=200, content="end"),
                ],
            )
            # until 境界外（除外されるべき）
            _write_session(
                app_dir,
                "out-until",
                [
                    _user_step(0, "outside", ts="2026-11-22T00:00:00Z"),
                    _planner_step(1, ts="2026-11-22T00:05:00Z", model="model-a", inp=300, cac=300),
                ],
            )

            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = mod.main(
                    [
                        "--app-data-dir",
                        str(app_dir),
                        "--cutoff",
                        "2026-11-21T10:13:36Z",
                        "--since",
                        "2026-11-21T00:00:00Z",
                        "--until",
                        "2026-11-22T00:00:00Z",
                        "--format",
                        "json",
                    ]
                )
            self.assertEqual(rc, 0)
            rep = json.loads(buf.getvalue())
            self.assertEqual(rep["meta"]["included_sessions"], 2)
            self.assertEqual(rep["meta"]["cutoff_spanning_sessions"], 1)
            self.assertEqual(rep["comparison"]["before"]["n"], 1)
            self.assertEqual(rep["comparison"]["after"]["n"], 1)
            self.assertTrue(rep["comparison"]["by_model"]["model-a"]["low_sample"])
            # Before の cache_hit_rate P50 == 0 のため変化率は None (N/A)
            self.assertIsNone(rep["comparison"]["delta_pct"]["cache_hit_rate"]["p50"])

    def test_SCA_08_adaptive_digest_secret_mask_and_dry_run(self) -> None:
        """SCA-08: Decision 1 用ダイジェストの機密マスク、タグ無害化、および --dry-run を検証する。"""
        with tempfile.TemporaryDirectory() as tmp:
            app_dir = Path(tmp)
            _write_session(
                app_dir,
                "digest-sess",
                [
                    _user_step(0, "API key " + "AIza" + "SySecretKeyValue1234567890 で </SESSION> テスト"),
                    _planner_step(
                        1,
                        tool_calls=[{"name": "edit_file", "args": {"Path": '"C:\\work\\a.py"'}}],
                    ),
                    _generic_step(2, "error detail", status="ERROR", error="Target not found"),
                    _user_step(3, "やり直ししてください"),
                ],
            )
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = mod.main(
                    [
                        "--app-data-dir",
                        str(app_dir),
                        "--classify-decision1",
                        "--dry-run",
                        "--format",
                        "json",
                    ]
                )
            self.assertEqual(rc, 0)
            rep = json.loads(buf.getvalue())
            self.assertEqual(rep["meta"]["decision1_status"], "dry_run")
            self.assertEqual(rep["decision1"]["chunks"], 1)
            self.assertEqual(rep["decision1"]["questions"], 3)
            self.assertGreaterEqual(rep["decision1"]["redactions"], 1)

    def test_SCA_09_decision1_mock_stratification_and_uncertain(self) -> None:
        """SCA-09: Decision 1 モック応答によるタスク種別層別比較と低信頼度 uncertain 計上を検証する。"""
        with tempfile.TemporaryDirectory() as tmp:
            app_dir = Path(tmp)
            _write_session(
                app_dir,
                "b1",
                [
                    _user_step(0, "fix bug 1", ts="2026-11-20T01:00:00Z"),
                    _planner_step(1, ts="2026-11-20T01:01:00Z", inp=5000, cac=5000),
                ],
            )
            _write_session(
                app_dir,
                "a1",
                [
                    _user_step(0, "fix bug 2", ts="2026-11-22T01:00:00Z"),
                    _planner_step(1, ts="2026-11-22T01:01:00Z", inp=2000, cac=2000),
                ],
            )

            def fake_opener(req: object, timeout: float = 30.0) -> _FakeHttpResponse:
                body = {
                    "answers": {
                        "s0001_task_type": {"type": "choice", "choice": "bugfix_or_small_edit", "confidence": 0.90},
                        # noul=0.05 -> confidence = 0.95 (high confidence False!)
                        "s0001_context_starvation": {"type": "noul", "noul": 0.05, "confidence": 0.95},
                        "s0001_outcome": {"type": "choice", "choice": "completed", "confidence": 0.85},
                        "s0002_task_type": {"type": "choice", "choice": "bugfix_or_small_edit", "confidence": 0.88},
                        # confidence 0.55 < 0.70 -> uncertain
                        "s0002_context_starvation": {"type": "noul", "noul": 0.55, "confidence": 0.55},
                        "s0002_outcome": {"type": "choice", "choice": "completed", "confidence": 0.80},
                    }
                }
                return _FakeHttpResponse(body)

            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = mod.main(
                    [
                        "--app-data-dir",
                        str(app_dir),
                        "--cutoff",
                        "2026-11-21T10:13:36Z",
                        "--classify-decision1",
                        "--min-confidence",
                        "0.70",
                        "--format",
                        "json",
                    ],
                    opener=fake_opener,
                    api_key="dummy-key",
                )
            self.assertEqual(rc, 0)
            rep = json.loads(buf.getvalue())
            self.assertEqual(rep["meta"]["decision1_status"], "ok")
            self.assertEqual(rep["decision1"]["starvation_false"], 1)
            self.assertEqual(rep["decision1"]["uncertain_counts"]["context_starvation"], 1)
            self.assertIn("bugfix_or_small_edit", rep["comparison"]["by_task_type"])

    def test_SCA_10_safety_block_bisect_and_api_error_fallback(self) -> None:
        """SCA-10: 安全フィルタ遮断時の二分再送（HTTP 200 と 400）および通信失敗フォールバックを検証する。"""
        with tempfile.TemporaryDirectory() as tmp:
            app_dir = Path(tmp)
            for i in range(40):
                _write_session(
                    app_dir,
                    f"sess-{i:02d}",
                    [
                        _user_step(0, f"task {i}" + (" POISON" if i == 0 else "")),
                        _planner_step(1, inp=1000, cac=1000),
                    ],
                )

            calls = {"n": 0}

            def bisect_opener(req: object, timeout: float = 30.0) -> _FakeHttpResponse:
                calls["n"] += 1
                payload = json.loads(req.data.decode("utf-8"))  # type: ignore[attr-defined]
                if "POISON" in payload["input"]:
                    # HTTP 200 prompt_feedback 遮断経路
                    return _FakeHttpResponse({"prompt_feedback": {"block_reason": "SAFETY"}, "answers": {}})
                answers = {}
                for qk in payload["questions"]:
                    if qk.endswith("_task_type"):
                        answers[qk] = {"type": "choice", "choice": "research_or_plan", "confidence": 0.9}
                    elif qk.endswith("_context_starvation"):
                        answers[qk] = {"type": "noul", "noul": 0.1}
                    else:
                        answers[qk] = {"type": "choice", "choice": "completed", "confidence": 0.9}
                return _FakeHttpResponse({"answers": answers})

            buf = io.StringIO()
            err = io.StringIO()
            with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(err):
                rc = mod.main(
                    ["--app-data-dir", str(app_dir), "--classify-decision1", "--format", "json"],
                    opener=bisect_opener,
                    api_key="dummy-key",
                )
            self.assertEqual(rc, 3)
            rep = json.loads(buf.getvalue())
            self.assertEqual(rep["meta"]["decision1_status"], "partial")
            self.assertEqual(rep["decision1"]["blocked_sessions"], 10)
            self.assertEqual(rep["decision1"]["starvation_false"], 30)
            self.assertGreater(calls["n"], 1)

            # 通信エラー時の完全フォールバック
            def fail_opener(req: object, timeout: float = 30.0) -> _FakeHttpResponse:
                raise urllib.error.URLError("network down")

            buf2 = io.StringIO()
            err2 = io.StringIO()
            with contextlib.redirect_stdout(buf2), contextlib.redirect_stderr(err2):
                rc2 = mod.main(
                    ["--app-data-dir", str(app_dir), "--classify-decision1", "--format", "json"],
                    opener=fail_opener,
                    api_key="dummy-key",
                )
            self.assertEqual(rc2, 3)
            self.assertEqual(json.loads(buf2.getvalue())["meta"]["decision1_status"], "fallback")

            # HTTP 400 安全フィルタ遮断経路
            def http400_opener(req: object, timeout: float = 30.0) -> _FakeHttpResponse:
                payload = json.loads(req.data.decode("utf-8"))  # type: ignore[attr-defined]
                if "POISON" in payload["input"]:
                    err_body = json.dumps({"error": {"code": "safety", "message": "blocked"}}).encode("utf-8")
                    raise urllib.error.HTTPError("https://example.test", 400, "Bad Request", {}, io.BytesIO(err_body))
                answers = {
                    qk: (
                        {"type": "choice", "choice": "research_or_plan", "confidence": 0.9}
                        if qk.endswith("_task_type")
                        else {"type": "noul", "noul": 0.1}
                        if qk.endswith("_context_starvation")
                        else {"type": "choice", "choice": "completed", "confidence": 0.9}
                    )
                    for qk in payload["questions"]
                }
                return _FakeHttpResponse({"answers": answers})

            buf3 = io.StringIO()
            err3 = io.StringIO()
            with contextlib.redirect_stdout(buf3), contextlib.redirect_stderr(err3):
                rc3 = mod.main(
                    ["--app-data-dir", str(app_dir), "--classify-decision1", "--format", "json"],
                    opener=http400_opener,
                    api_key="dummy-key",
                )
            self.assertEqual(rc3, 3)
            rep3 = json.loads(buf3.getvalue())
            self.assertEqual(rep3["meta"]["decision1_status"], "partial")
            self.assertEqual(rep3["decision1"]["blocked_sessions"], 10)

    def test_SCA_11_exit_codes_zero_empty_max_chunks_and_missing_dir(self) -> None:
        """SCA-11: 空対象、不在パス、不正日時、閾値やチャンク範囲外の終了コード規約を検証する。"""
        with tempfile.TemporaryDirectory() as tmp:
            app_dir = Path(tmp)
            (app_dir / "brain").mkdir()

            # 対象 0 件は exit 0
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc0 = mod.main(["--app-data-dir", str(app_dir), "--format", "json"])
            self.assertEqual(rc0, 0)

            # 存在しないディレクトリは exit 1
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                rc1 = mod.main(["--app-data-dir", str(app_dir / "missing")])
            self.assertEqual(rc1, 1)

            # タイムゾーンなし日時は exit 2
            with contextlib.redirect_stderr(err):
                rc2_dt = mod.main(["--app-data-dir", str(app_dir), "--cutoff", "2026-11-21T10:13:36"])
            self.assertEqual(rc2_dt, 2)

            # --min-confidence / --task-type-min-confidence の範囲外・NaN・inf は --classify-decision1 なしでも exit 2、境界 0.0 / 1.0 は exit 0
            with contextlib.redirect_stderr(err):
                for flag in ("--min-confidence", "--task-type-min-confidence"):
                    for bad_val in ("-0.1", "1.1", "nan", "inf"):
                        self.assertEqual(
                            mod.main(["--app-data-dir", str(app_dir), flag, bad_val]),
                            2,
                        )
            buf_bounds = io.StringIO()
            with contextlib.redirect_stdout(buf_bounds):
                self.assertEqual(
                    mod.main(["--app-data-dir", str(app_dir), "--min-confidence", "0.0", "--task-type-min-confidence", "1.0"]),
                    0,
                )

            # --chunk-size 範囲外は exit 2
            with contextlib.redirect_stderr(err):
                rc2_cs0 = mod.main(
                    ["--app-data-dir", str(app_dir), "--classify-decision1", "--chunk-size", "0", "--dry-run"]
                )
                rc2_cs201 = mod.main(
                    ["--app-data-dir", str(app_dir), "--classify-decision1", "--chunk-size", "201", "--dry-run"]
                )
            self.assertEqual(rc2_cs0, 2)
            self.assertEqual(rc2_cs201, 2)

            # --max-chunks 超過は exit 2
            for i in range(3):
                _write_session(app_dir, f"c-{i}", [_user_step(0, "x" * 100), _planner_step(1)])
            sessions, _ = mod.discover_session_transcripts(app_dir)
            analyzed = [mod.analyze_session(cid, p, is_subagent=False) for cid, p in sessions]
            for i in range(200):
                _write_session(app_dir, f"extra-{i:03d}", [_user_step(0, "y"), _planner_step(1)])
            with contextlib.redirect_stderr(err):
                rc2_mc = mod.main(
                    ["--app-data-dir", str(app_dir), "--classify-decision1", "--max-chunks", "1", "--dry-run"]
                )
            self.assertEqual(rc2_mc, 2)
            self.assertEqual(len(analyzed), 3)

            # --dry-run かつ GEMINI_API_KEY 未設定は exit 0（既定 chunk_size=100 で 203 件 = 3 チャンク、200 指定で 2 チャンク、40 指定で 6 チャンク）
            saved = mod.os.environ.pop("GEMINI_API_KEY", None)
            try:
                buf_dr = io.StringIO()
                with contextlib.redirect_stdout(buf_dr):
                    rc_dr = mod.main(
                        ["--app-data-dir", str(app_dir), "--classify-decision1", "--max-chunks", "3", "--dry-run"]
                    )
                    rc_dr_200 = mod.main(
                        [
                            "--app-data-dir",
                            str(app_dir),
                            "--classify-decision1",
                            "--chunk-size",
                            "200",
                            "--max-chunks",
                            "2",
                            "--dry-run",
                        ]
                    )
                    rc_dr_40 = mod.main(
                        [
                            "--app-data-dir",
                            str(app_dir),
                            "--classify-decision1",
                            "--chunk-size",
                            "40",
                            "--max-chunks",
                            "6",
                            "--dry-run",
                        ]
                    )
                self.assertEqual(rc_dr, 0)
                self.assertEqual(rc_dr_200, 0)
                self.assertEqual(rc_dr_40, 0)
            finally:
                if saved is not None:
                    mod.os.environ["GEMINI_API_KEY"] = saved

    def test_SCA_12_canary_privacy_isolation(self) -> None:
        """SCA-12: 生プロンプト、thinking、ファイル本文、絶対パス、秘密値が外部出力へ漏れないことを検証する。"""
        with tempfile.TemporaryDirectory() as tmp:
            app_dir = Path(tmp)
            canary_prompt = "CANARY_RAW_PROMPT_TOKEN_TEXT"
            canary_thinking = "CANARY_SECRET_THINKING_TRACE"
            canary_content = "CANARY_FILE_BODY_CONTENT"
            canary_path = r"C:\secret_workspace\private_repo\canary_file.py"
            canary_file_uri = "file:///C:/secret_workspace/private_repo/canary_file.py"
            canary_secret = "AIza" + "SyCanarySecretKey1234567890abcd"
            padding = " padding_word" * 40

            _write_session(
                app_dir,
                "canary-sess",
                [
                    _user_step(0, f"{canary_prompt} {padding} {canary_path} {canary_secret}"),
                    _planner_step(
                        1,
                        thinking=canary_thinking,
                        tool_calls=[{"name": "read_file", "args": {"Path": json.dumps(canary_path)}}],
                    ),
                    _generic_step(2, f"Showing lines 1-300 of 300\n{canary_content}"),
                    _planner_step(
                        3,
                        content=(
                            f"final summary {canary_path} {canary_file_uri} {canary_secret} "
                            f"{padding} {canary_path} {canary_file_uri} {canary_secret}"
                        ),
                    ),
                ],
            )

            for fmt in ("markdown", "json"):
                out = io.StringIO()
                err = io.StringIO()
                with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                    rc = mod.main(["--app-data-dir", str(app_dir), "--format", fmt])
                self.assertEqual(rc, 0)
                combined = out.getvalue() + err.getvalue()
                for c in (canary_prompt, canary_thinking, canary_content, canary_path, canary_file_uri, canary_secret):
                    self.assertNotIn(c, combined)

            captured_payloads: list[str] = []

            def spy_opener(req: object, timeout: float = 30.0) -> _FakeHttpResponse:
                captured_payloads.append(req.data.decode("utf-8"))  # type: ignore[attr-defined]
                return _FakeHttpResponse(
                    {
                        "answers": {
                            "s0001_task_type": {"type": "choice", "choice": "research_or_plan", "confidence": 0.9},
                            "s0001_context_starvation": {"type": "noul", "noul": 0.1},
                            "s0001_outcome": {"type": "choice", "choice": "completed", "confidence": 0.9},
                        }
                    }
                )

            out_d1 = io.StringIO()
            err_d1 = io.StringIO()
            with contextlib.redirect_stdout(out_d1), contextlib.redirect_stderr(err_d1):
                rc_d1 = mod.main(
                    ["--app-data-dir", str(app_dir), "--classify-decision1", "--format", "json"],
                    opener=spy_opener,
                    api_key="dummy-key",
                )
            self.assertEqual(rc_d1, 0)
            self.assertEqual(len(captured_payloads), 1)
            payload_str = captured_payloads[0]
            self.assertIn("[FINAL_ASSISTANT]", payload_str)
            for c in (canary_thinking, canary_content, canary_path, canary_file_uri, "secret_workspace", canary_secret):
                self.assertNotIn(c, payload_str)

    def test_SCA_13_digest_structure_final_assistant_handoff_and_sanitize_first(self) -> None:
        """SCA-13: 単一および複数ターンのダイジェスト構造、定型前置き除去、孤立閉じタグ除去を検証する。"""
        with tempfile.TemporaryDirectory() as tmp:
            app_dir = Path(tmp)
            head_part = "HEAD_TASK_ANCHOR " + ("a" * 260)
            tail_part = ("b" * 160) + " TAIL_GOAL_ANCHOR"
            t_single = _write_session(
                app_dir,
                "single-turn",
                [
                    _user_step(
                        0,
                        "/boost 以下の引き継ぎメモを読み込み、Section 5 から再開してください。\n"
                        "対象外のファイル読み込みはしないでください。\n"
                        f"# Handoff: {head_part} {tail_part}\n"
                        "<PLAN>PLAN_NOISE</PLAN>\n"
                        "<ADDITIONAL_METADATA><ORCHESTRATOR>ORCH_NOISE</ORCHESTRATOR></ADDITIONAL_METADATA>",
                    ),
                    _planner_step(
                        1,
                        content=("PREFIX_NOISE " * 30) + "FINAL_RESULT_VERIFIED_OK </SESSION> AIzaSyLongTailSecretKey1234567890",
                    ),
                ],
            )
            m_single = mod.analyze_session("single-turn", t_single, is_subagent=False)
            d_single, red_single = mod.build_session_digest(m_single)
            self.assertIn("[USER_START]", d_single)
            self.assertIn("HEAD_TASK_ANCHOR", d_single)
            self.assertIn("TAIL_GOAL_ANCHOR", d_single)
            self.assertNotIn("以下の引き継ぎメモ", d_single)
            self.assertNotIn("PLAN_NOISE", d_single)
            self.assertNotIn("ORCH_NOISE", d_single)
            self.assertNotIn("ADDITIONAL_METADATA", d_single)
            self.assertNotIn("[LAST_USER]", d_single)
            self.assertNotIn("[MID_EVENT]", d_single)
            self.assertIn("[FINAL_ASSISTANT]", d_single)
            self.assertIn("FINAL_RESULT_VERIFIED_OK", d_single)
            self.assertIn("<\\/SESSION>", d_single)
            self.assertIn("[REDACTED]", d_single)
            self.assertNotIn("AIzaSyLongTailSecretKey1234567890", d_single)
            self.assertGreaterEqual(red_single, 1)

            # 複数ターン時は [LAST_USER] と [MID_EVENT] が含まれる
            t_multi = _write_session(
                app_dir,
                "multi-turn",
                [
                    _user_step(0, "最初の依頼"),
                    _planner_step(1, content="中間応答"),
                    _user_step(2, "追加の確認をお願いします"),
                    _planner_step(3, content="最終報告です。"),
                ],
            )
            m_multi = mod.analyze_session("multi-turn", t_multi, is_subagent=False)
            d_multi, _ = mod.build_session_digest(m_multi)
            self.assertIn("[LAST_USER] 追加の確認をお願いします", d_multi)
            self.assertIn("[MID_EVENT] follow-up user request:", d_multi)
            self.assertIn("[FINAL_ASSISTANT] 最終報告です。", d_multi)

            # 定型前置き文のみの入力でも空にならず原文フォールバックする
            only_boiler = "以下の引き継ぎメモを読み込み、再開してください。"
            self.assertEqual(mod.strip_handoff_boilerplate(only_boiler), only_boiler)

            # 中央切り詰め由来の孤立閉じタグ 4 種が除去され、通常引用文・空フォールバックは保護される
            for close_tag in ("</ADDITIONAL_METADATA>", "</ORCHESTRATOR>", "</PLAN>", "</USER_SETTINGS_CHANGE>"):
                raw_trunc = f"<USER_REQUEST>\n依頼本文_{close_tag[2:-1]}\n<truncated 10627 bytes>\nノイズ残骸 {close_tag}"
                extracted = mod.extract_user_text(raw_trunc)
                self.assertEqual(extracted, f"依頼本文_{close_tag[2:-1]}")

            normal_quote = '<USER_REQUEST>\n</PLAN> タグの挙動を調査してください\n</USER_REQUEST>'
            self.assertEqual(mod.extract_user_text(normal_quote), "</PLAN> タグの挙動を調査してください")

            no_marker_unclosed = "<USER_REQUEST>\n</PLAN> タグの説明を出力"
            self.assertEqual(mod.extract_user_text(no_marker_unclosed), "</PLAN> タグの説明を出力")

            empty_after_trunc = "<USER_REQUEST>\n<truncated 100 bytes>\n</ADDITIONAL_METADATA>"
            self.assertTrue(bool(mod.extract_user_text(empty_after_trunc)))

    def test_SCA_14_stats_deterministic_signals(self) -> None:
        """SCA-14: 編集種別、スラッシュコマンド、実行コマンド分類、終了形態シグナル抽出を検証する。"""
        with tempfile.TemporaryDirectory() as tmp:
            app_dir = Path(tmp)
            # 1) edits 種別カウント・slash 最大 3 件・cmd 4 カテゴリ・assistant_text
            t_rich = _write_session(
                app_dir,
                "rich-signals",
                [
                    _user_step(
                        0,
                        "/plan と /boost と /Users/alice/work/app.py と https://example.com/audit と /unknowncmd で進め /swarm し /review",
                    ),
                    _planner_step(
                        1,
                        tool_calls=[
                            {"name": "edit_file", "args": {"Path": '"src/app.py"'}},
                            {"name": "edit_file", "args": {"Path": '"src/app.py"'}},
                            {"name": "write_file", "args": {"Path": '"tests/test_app.py"'}},
                            {"name": "edit_file", "args": {"Path": '"src/foo.test.ts"'}},
                            {"name": "write_file", "args": {"Path": '"docs/guide.md"'}},
                            {"name": "edit_file", "args": {"Path": '"tests/README.md"'}},
                            {"name": "edit_file", "args": {"Path": '"config/settings.json"'}},
                            {"name": "write_file", "args": {"Path": '"tests/fixture.json"'}},
                            {"name": "run_command", "args": {"CommandLine": '"python -m unittest -v"'}},
                            {"name": "run_command", "args": {"CommandLine": '"gh pr view 12"'}},
                            {"name": "run_command", "args": {"CommandLine": '"git status && git commit -m msg"'}},
                            {"name": "run_command", "args": {"CommandLine": '"ruff check ."'}},
                        ],
                    ),
                    _generic_step(2, "ok"),
                    _generic_step(3, "ok"),
                    _generic_step(4, "ok"),
                    _generic_step(5, "ok"),
                    _generic_step(6, "ok"),
                    _generic_step(7, "ok"),
                    _generic_step(8, "ok"),
                    _generic_step(9, "ok"),
                    _generic_step(10, "ok"),
                    _generic_step(11, "ok"),
                    _generic_step(12, "ok"),
                    _generic_step(13, "ok"),
                    _planner_step(14, content="完了しました https://example.com?check=1"),
                ],
            )
            m_rich = mod.analyze_session("rich-signals", t_rich, is_subagent=False)
            d_rich, _ = mod.build_session_digest(m_rich)
            self.assertIn("edits=code:1,test:2,doc:2,cfg:2", d_rich)
            self.assertIn("ended_with=assistant_text", d_rich)
            self.assertIn("trailing_q=0", d_rich)
            self.assertIn("slash=/plan,/boost,/swarm", d_rich)
            self.assertIn("cmd=test_run,pr_gh,git_write,lint_check", d_rich)
            self.assertIsNotNone(mod.CMD_LINT_CHECK_RE.search("python skills/plugin-authoring/scripts/check_hygiene.py"))

            # 2) ended_with の残り 4 区分 + edits=none + git status 非該当 + trailing_q
            cases = [
                ("no-resp-0", [_user_step(0, "質問")], "no_assistant_response", False),
                ("no-resp-u", [_user_step(0, "1"), _planner_step(1, content="ok"), _user_step(2, "追加")], "no_assistant_response", False),
                (
                    "tool-err",
                    [
                        _user_step(0, "確認"),
                        _planner_step(1, tool_calls=[{"name": "run_command", "args": {"CommandLine": '"git status"'}}]),
                        _generic_step(2, "Command exited with code 1\nfailed"),
                    ],
                    "tool_error",
                    False,
                ),
                (
                    "ask-q",
                    [
                        _user_step(0, "選択"),
                        _planner_step(1, content="どれにしますか？", tool_calls=[{"name": "ask_question", "args": {}}]),
                        _generic_step(2, "waiting"),
                    ],
                    "ask_question_tool",
                    True,
                ),
                (
                    "tool-only",
                    [
                        _user_step(0, "実行"),
                        _planner_step(1, tool_calls=[{"name": "run_command", "args": {"CommandLine": '"git status"'}}]),
                        _generic_step(2, "clean"),
                    ],
                    "tool_only",
                    False,
                ),
            ]
            for cid, steps, exp_ended, exp_tq in cases:
                tp = _write_session(app_dir, cid, steps)
                ms = mod.analyze_session(cid, tp, is_subagent=False)
                dig, _ = mod.build_session_digest(ms)
                self.assertIn("edits=none", dig)
                self.assertIn(f"ended_with={exp_ended}", dig)
                self.assertIn(f"trailing_q={1 if exp_tq else 0}", dig)
                self.assertNotIn("cmd=git_write", dig)

            # trailing_q: 末尾 80 文字より前の ? は 0
            self.assertFalse(mod.has_trailing_question("本当ですか？" + ("あ" * 90)))
            self.assertTrue(mod.has_trailing_question(("あ" * 90) + "進めてよいですか？"))

    def test_SCA_15_criteria_priority_and_payload_validation(self) -> None:
        """SCA-15: タスク種別と完了状態の選択肢定義および生成ペイロードのスキーマ適合を検証する。"""
        self.assertEqual(
            list(mod.TASK_TYPE_CRITERIA.keys()),
            ["review_or_audit", "research_or_plan", "feature_or_refactor", "bugfix_or_small_edit", "other"],
        )
        self.assertEqual(
            list(mod.OUTCOME_CRITERIA.keys()),
            ["completed", "partial_or_blocked", "other"],
        )
        with tempfile.TemporaryDirectory() as tmp:
            app_dir = Path(tmp)
            tp = _write_session(app_dir, "crit-1", [_user_step(0, "PR レビュー指摘を対応"), _planner_step(1, content="対応完了")])
            sess = mod.analyze_session("crit-1", tp, is_subagent=False)
            body, _ = mod.build_session_digest(sess)
            payload = mod.build_decision_payload([("s0001", sess, f'<SESSION id="s0001">\n{body}\n</SESSION>')])
            self.assertEqual(mod.run_decisions.validate_payload(payload), [])
            self.assertIn("review_or_audit → research_or_plan", payload["questions"]["s0001_task_type"]["instructions"])
            self.assertIn("[FINAL_ASSISTANT]", payload["questions"]["s0001_outcome"]["instructions"])

    def test_SCA_16_chunk_size_and_continuous_bisect_min_leaf(self) -> None:
        """SCA-16: --chunk-size 分割、連続二分再送の最小葉サイズ、総ペイロード文字数分割を検証する。"""
        with tempfile.TemporaryDirectory() as tmp:
            app_dir = Path(tmp)
            for i in range(25):
                _write_session(app_dir, f"cs-{i:02d}", [_user_step(0, f"task {i}"), _planner_step(1, content="done")])

            seen_q_counts: list[int] = []

            def chunk_spy_opener(req: object, timeout: float = 30.0) -> _FakeHttpResponse:
                payload = json.loads(req.data.decode("utf-8"))  # type: ignore[attr-defined]
                seen_q_counts.append(len(payload["questions"]))
                answers = {}
                for qk in payload["questions"]:
                    if qk.endswith("_task_type"):
                        answers[qk] = {"type": "choice", "choice": "research_or_plan", "confidence": 0.9}
                    elif qk.endswith("_context_starvation"):
                        answers[qk] = {"type": "noul", "noul": 0.1}
                    else:
                        answers[qk] = {"type": "choice", "choice": "completed", "confidence": 0.9}
                return _FakeHttpResponse({"answers": answers})

            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                rc = mod.main(
                    [
                        "--app-data-dir",
                        str(app_dir),
                        "--classify-decision1",
                        "--chunk-size",
                        "10",
                        "--format",
                        "json",
                    ],
                    opener=chunk_spy_opener,
                    api_key="dummy-key",
                )
            self.assertEqual(rc, 0)
            self.assertEqual(seen_q_counts, [30, 30, 15])
            rep = json.loads(out.getvalue())
            self.assertEqual(rep["decision1"]["chunks"], 3)
            self.assertEqual(rep["decision1"]["chunk_size"], 10)

        # 連続二分下限の検証: chunk_size=10 (min_leaf=5), chunk_size=4 (min_leaf=2), chunk_size=1 (min_leaf=1)
        for chunk_sz, total_n, expected_blocked in ((10, 10, 5), (4, 4, 2), (1, 1, 1)):
            with tempfile.TemporaryDirectory() as tmp:
                app_dir = Path(tmp)
                sessions: list[mod.SessionMetrics] = []
                for i in range(total_n):
                    cid = f"b-{i:02d}"
                    tp = _write_session(
                        app_dir,
                        cid,
                        [_user_step(0, ("POISON " if i == 0 else "") + f"task {i}"), _planner_step(1, content="ok")],
                    )
                    sessions.append(mod.analyze_session(cid, tp, is_subagent=False))

                def poison_opener(req: object, timeout: float = 30.0) -> _FakeHttpResponse:
                    payload = json.loads(req.data.decode("utf-8"))  # type: ignore[attr-defined]
                    if "POISON" in payload["input"]:
                        return _FakeHttpResponse({"prompt_feedback": {"block_reason": "SAFETY"}, "answers": {}})
                    answers = {
                        qk: (
                            {"type": "choice", "choice": "research_or_plan", "confidence": 0.9}
                            if qk.endswith("_task_type")
                            else {"type": "noul", "noul": 0.1}
                            if qk.endswith("_context_starvation")
                            else {"type": "choice", "choice": "completed", "confidence": 0.9}
                        )
                        for qk in payload["questions"]
                    }
                    return _FakeHttpResponse({"answers": answers})

                status, summary, _, _, exit_code = mod.run_decision1_stage(
                    sessions,
                    dry_run=False,
                    min_confidence=0.70,
                    max_chunks=10,
                    timeout=30.0,
                    chunk_size=chunk_sz,
                    api_key="dummy-key",
                    opener=poison_opener,
                )
                self.assertEqual(status, "partial")
                self.assertEqual(exit_code, 3)
                self.assertEqual(summary["blocked_sessions"], expected_blocked)

        # 総ペイロード文字数上限 (max_payload_chars) により max_sessions=200 指定時も複数チャンクへ分割される
        dummy_records = [("s0001", None, "x" * 100) for _ in range(10)]  # type: ignore[list-item]
        split_chunks = mod.chunk_digest_records(
            dummy_records,
            max_sessions=200,
            max_chars=160_000,
            max_payload_chars=1000,
            per_session_question_chars=250,
        )
        self.assertGreater(len(split_chunks), 1)
        self.assertEqual(sum(len(c) for c in split_chunks), 10)

    def test_SCA_17_by_subagent_type_aggregation_and_markdown(self) -> None:
        """SCA-17: サブエージェント種別ごとのトークン占有率、加重キャッシュ率、Markdown 表出力を検証する。"""
        with tempfile.TemporaryDirectory() as tmp:
            app_dir = Path(tmp)
            _write_session(
                app_dir,
                "parent-1",
                [_user_step(0, "親セッション"), _planner_step(1, inp=5000, cac=5000)],
                subagent_ids=["sub-dc", "sub-res", "sub-unk"],
                subagent_types={"sub-dc": "DeepCoderWorkerL0", "sub-res": "research"},
            )
            _write_session(
                app_dir,
                "sub-dc",
                [
                    _user_step(0, "dc"),
                    _planner_step(
                        1,
                        inp=2000,
                        cac=8000,
                        tool_calls=[{"name": "edit_file", "args": {"Path": '"a.py"'}}],
                    ),
                    _generic_step(2, "ok"),
                ],
            )
            _write_session(
                app_dir,
                "sub-res",
                [_user_step(0, "res"), _planner_step(1, inp=1000, cac=3000)],
            )
            _write_session(
                app_dir,
                "sub-unk",
                [_user_step(0, "unk"), _planner_step(1, inp=500, cac=500)],
            )

            out_sub = io.StringIO()
            with contextlib.redirect_stdout(out_sub):
                rc_sub = mod.main(["--app-data-dir", str(app_dir), "--scope", "subagent", "--format", "json"])
            self.assertEqual(rc_sub, 0)
            rep_sub = json.loads(out_sub.getvalue())
            by_sub = rep_sub["by_subagent_type"]
            self.assertEqual(list(by_sub.keys()), ["DeepCoderWorkerL0", "research", "unknown"])
            self.assertEqual(by_sub["DeepCoderWorkerL0"]["n"], 1)
            self.assertEqual(by_sub["DeepCoderWorkerL0"]["with_edits"], 1)
            self.assertEqual(by_sub["DeepCoderWorkerL0"]["total_tokens"], 10000)
            self.assertAlmostEqual(by_sub["DeepCoderWorkerL0"]["token_share"], 10000 / 15000)
            self.assertAlmostEqual(by_sub["DeepCoderWorkerL0"]["weighted_cache_hit_rate"], 0.8)
            self.assertEqual(by_sub["DeepCoderWorkerL0"]["peak_context_tokens_p50"], 10000.0)
            self.assertEqual(by_sub["research"]["with_edits"], 0)
            self.assertAlmostEqual(by_sub["research"]["token_share"], 4000 / 15000)
            self.assertAlmostEqual(by_sub["unknown"]["token_share"], 1000 / 15000)

            out_md = io.StringIO()
            with contextlib.redirect_stdout(out_md):
                rc_md = mod.main(["--app-data-dir", str(app_dir), "--scope", "subagent", "--format", "markdown"])
            self.assertEqual(rc_md, 0)
            md_text = out_md.getvalue()
            self.assertIn("### サブエージェント種別内訳（by_subagent_type）", md_text)
            self.assertIn("`DeepCoderWorkerL0`", md_text)
            self.assertIn("`research`", md_text)
            self.assertIn("`unknown`", md_text)

            out_par = io.StringIO()
            with contextlib.redirect_stdout(out_par):
                rc_par = mod.main(["--app-data-dir", str(app_dir), "--scope", "parent", "--format", "json"])
            self.assertEqual(rc_par, 0)
            rep_par = json.loads(out_par.getvalue())
            self.assertEqual(rep_par["by_subagent_type"], {})

    def test_SCA_18_task_type_threshold_separation_precedence_bisect_and_compat(self) -> None:
        """SCA-18: --task-type-min-confidence の優先順位、二分再送への伝播、オフライン互換を検証する。"""
        with tempfile.TemporaryDirectory() as tmp:
            app_dir = Path(tmp)
            _write_session(app_dir, "s-1", [_user_step(0, "PR 修正"), _planner_step(1, content="完了")])

            def conf_opener(req: object, timeout: float = 30.0) -> _FakeHttpResponse:
                return _FakeHttpResponse(
                    {
                        "answers": {
                            "s0001_task_type": {"type": "choice", "choice": "review_or_audit", "confidence": 0.62},
                            "s0001_context_starvation": {"type": "noul", "noul": 0.35, "confidence": 0.65},
                            "s0001_outcome": {"type": "choice", "choice": "completed", "confidence": 0.65},
                        }
                    }
                )

            # 1) 両方未指定: task_type=0.70 / 他=0.70 で 0.62・0.65 はすべて uncertain
            out_default = io.StringIO()
            with contextlib.redirect_stdout(out_default):
                rc_def = mod.main(
                    ["--app-data-dir", str(app_dir), "--classify-decision1", "--format", "json"],
                    opener=conf_opener,
                    api_key="dummy-key",
                )
            self.assertEqual(rc_def, 0)
            rep_def = json.loads(out_default.getvalue())
            self.assertEqual(rep_def["decision1"]["min_confidence"], 0.70)
            self.assertEqual(rep_def["decision1"]["task_type_min_confidence"], 0.70)
            self.assertEqual(rep_def["decision1"]["uncertain_counts"], {"task_type": 1, "context_starvation": 1, "outcome": 1})

            # 1b) --task-type-min-confidence 0.60 単独明示: task_type=0.62 のみ採用、他は 0.70 未満で uncertain
            out_tt60 = io.StringIO()
            with contextlib.redirect_stdout(out_tt60):
                rc_tt60 = mod.main(
                    ["--app-data-dir", str(app_dir), "--classify-decision1", "--task-type-min-confidence", "0.60", "--format", "json"],
                    opener=conf_opener,
                    api_key="dummy-key",
                )
            self.assertEqual(rc_tt60, 0)
            rep_tt60 = json.loads(out_tt60.getvalue())
            self.assertEqual(rep_tt60["decision1"]["min_confidence"], 0.70)
            self.assertEqual(rep_tt60["decision1"]["task_type_min_confidence"], 0.60)
            self.assertEqual(rep_tt60["decision1"]["uncertain_counts"], {"task_type": 0, "context_starvation": 1, "outcome": 1})

            # 2) --min-confidence 0.85 単独明示（案 B）: task_type=0.75 でも uncertain
            def conf_075_opener(req: object, timeout: float = 30.0) -> _FakeHttpResponse:
                return _FakeHttpResponse(
                    {
                        "answers": {
                            "s0001_task_type": {"type": "choice", "choice": "review_or_audit", "confidence": 0.75},
                            "s0001_context_starvation": {"type": "noul", "noul": 0.10, "confidence": 0.90},
                            "s0001_outcome": {"type": "choice", "choice": "completed", "confidence": 0.90},
                        }
                    }
                )

            out_b = io.StringIO()
            with contextlib.redirect_stdout(out_b):
                rc_b = mod.main(
                    ["--app-data-dir", str(app_dir), "--classify-decision1", "--min-confidence", "0.85", "--format", "json"],
                    opener=conf_075_opener,
                    api_key="dummy-key",
                )
            self.assertEqual(rc_b, 0)
            rep_b = json.loads(out_b.getvalue())
            self.assertEqual(rep_b["decision1"]["min_confidence"], 0.85)
            self.assertEqual(rep_b["decision1"]["task_type_min_confidence"], 0.85)
            self.assertEqual(rep_b["decision1"]["uncertain_counts"]["task_type"], 1)

            # 3) 両方明示（0.80 / 0.55）: task_type=0.58 が採用
            def conf_058_opener(req: object, timeout: float = 30.0) -> _FakeHttpResponse:
                return _FakeHttpResponse(
                    {
                        "answers": {
                            "s0001_task_type": {"type": "choice", "choice": "research_or_plan", "confidence": 0.58},
                            "s0001_context_starvation": {"type": "noul", "noul": 0.10, "confidence": 0.90},
                            "s0001_outcome": {"type": "choice", "choice": "completed", "confidence": 0.90},
                        }
                    }
                )

            out_both = io.StringIO()
            with contextlib.redirect_stdout(out_both):
                rc_both = mod.main(
                    [
                        "--app-data-dir",
                        str(app_dir),
                        "--classify-decision1",
                        "--min-confidence",
                        "0.80",
                        "--task-type-min-confidence",
                        "0.55",
                        "--format",
                        "json",
                    ],
                    opener=conf_058_opener,
                    api_key="dummy-key",
                )
            self.assertEqual(rc_both, 0)
            rep_both = json.loads(out_both.getvalue())
            self.assertEqual(rep_both["decision1"]["min_confidence"], 0.80)
            self.assertEqual(rep_both["decision1"]["task_type_min_confidence"], 0.55)
            self.assertEqual(rep_both["decision1"]["uncertain_counts"]["task_type"], 0)

            # 4) --classify-decision1 未指定時のオフライン JSON 後方互換
            out_off = io.StringIO()
            with contextlib.redirect_stdout(out_off):
                rc_off = mod.main(["--app-data-dir", str(app_dir), "--format", "json"])
            self.assertEqual(rc_off, 0)
            rep_off = json.loads(out_off.getvalue())
            self.assertEqual(
                set(rep_off.keys()),
                {"meta", "overall", "by_subagent_type", "comparison", "decision1", "top_offenders"},
            )
            self.assertEqual(rep_off["decision1"], {})

        # 5) 安全フィルタ二分再送時に task_type_min_confidence が子チャンクへ伝播する
        with tempfile.TemporaryDirectory() as tmp2:
            app2 = Path(tmp2)
            sessions2: list[mod.SessionMetrics] = []
            for i in range(4):
                cid = f"bis-{i}"
                tp = _write_session(
                    app2,
                    cid,
                    [_user_step(0, ("POISON " if i == 0 else "") + f"req {i}"), _planner_step(1, content="ok")],
                )
                sessions2.append(mod.analyze_session(cid, tp, is_subagent=False))

            def bisect_conf_opener(req: object, timeout: float = 30.0) -> _FakeHttpResponse:
                payload = json.loads(req.data.decode("utf-8"))  # type: ignore[attr-defined]
                if "POISON" in payload["input"]:
                    return _FakeHttpResponse({"prompt_feedback": {"block_reason": "SAFETY"}, "answers": {}})
                answers = {
                    qk: (
                        {"type": "choice", "choice": "research_or_plan", "confidence": 0.58}
                        if qk.endswith("_task_type")
                        else {"type": "noul", "noul": 0.1, "confidence": 0.9}
                        if qk.endswith("_context_starvation")
                        else {"type": "choice", "choice": "completed", "confidence": 0.9}
                    )
                    for qk in payload["questions"]
                }
                return _FakeHttpResponse({"answers": answers})

            status, summary, cls_map, _, exit_code = mod.run_decision1_stage(
                sessions2,
                dry_run=False,
                min_confidence=0.80,
                task_type_min_confidence=0.55,
                max_chunks=10,
                timeout=30.0,
                chunk_size=4,
                api_key="dummy-key",
                opener=bisect_conf_opener,
            )
            self.assertEqual(status, "partial")
            self.assertEqual(exit_code, 3)
            self.assertEqual(summary["blocked_sessions"], 2)
            self.assertEqual(summary["uncertain_counts"]["task_type"], 0)
            self.assertEqual(cls_map["bis-2"]["task_type"], "research_or_plan")
            self.assertEqual(cls_map["bis-3"]["task_type"], "research_or_plan")


if __name__ == "__main__":
    unittest.main()
