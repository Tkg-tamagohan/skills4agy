#!/usr/bin/env python3
"""pr_guardrails.py の単体テストおよび invariant-gate 結合テスト（PRG-UT-01〜PRG-UT-18）。"""

from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest

_SCRIPT_DIR = Path(__file__).resolve().parent
if str(_SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPT_DIR))

_INVARIANT_GATE_SCRIPTS_DIR = Path(__file__).resolve().parents[2] / "invariant-gate" / "scripts"
if str(_INVARIANT_GATE_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_INVARIANT_GATE_SCRIPTS_DIR))

import check_invariants_decision1 as cid  # noqa: E402
import pr_guardrails as pg  # noqa: E402


def _run_cli(argv: list[str], stdin_text: str | None = None) -> tuple[int, str, str]:
    stdout_buf = io.StringIO()
    stderr_buf = io.StringIO()
    orig_stdin = sys.stdin
    try:
        if stdin_text is not None:
            sys.stdin = io.StringIO(stdin_text)
        with redirect_stdout(stdout_buf), redirect_stderr(stderr_buf):
            code = pg.main(argv)
    finally:
        sys.stdin = orig_stdin
    return code, stdout_buf.getvalue(), stderr_buf.getvalue()


def _write_json(path: Path, data: object) -> str:
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8", newline="\n")
    return str(path)


class PrGuardrailsTests(unittest.TestCase):
    """PR 内再発防止策 CLI の仕様ベース単体テスト・結合テスト。"""

    def test_prg_ut_01_single_comment_extract_and_next_id(self) -> None:
        """PRG-UT-01: 単一 PR コメントのマーカーブロックから複数 active 項目を抽出し next_id を計算できる。"""
        pr_data = {
            "comments": [
                {
                    "id": "IC_1",
                    "author": {"login": "alice"},
                    "createdAt": "2026-11-20T10:00:00Z",
                    "body": "\n".join(
                        [
                            "サマリ本文です。",
                            pg.MARKER_START,
                            "## 再発防止策（PR 内引き継ぎ）",
                            "",
                            "- [PRG-001] (active) 対象: `src/ipc/**` | ルール: IPC エラーを呼び出し元へ返す | 根拠: commit `aaa1111`",
                            "- [PRG-002] (active) 対象: `src/net/**` | ルール: IPv4-mapped IPv6 を正規化する | 根拠: thread `PRRT_2`",
                            pg.MARKER_END,
                        ]
                    ),
                }
            ]
        }
        with tempfile.TemporaryDirectory() as tmp:
            in_path = _write_json(Path(tmp) / "pr.json", pr_data)
            code, out, err = _run_cli(["extract", "--input", in_path, "--format", "json"])
        self.assertEqual(code, 0, err)
        payload = json.loads(out)
        self.assertEqual(payload["active_count"], 2)
        self.assertEqual(payload["retired_count"], 0)
        self.assertEqual(payload["next_id"], "PRG-003")
        self.assertEqual(payload["source_blocks_count"], 1)
        self.assertEqual([item["id"] for item in payload["active"]], ["PRG-001", "PRG-002"])
        self.assertEqual(payload["active"][0]["source"]["author"], "alice")

    def test_prg_ut_02_chronological_last_write_wins(self) -> None:
        """PRG-UT-02: 複数コメントの時系列マージで同一 ID の改訂が後勝ち上書きされる。"""
        pr_data = {
            "comments": [
                {
                    "id": "IC_NEW",
                    "author": {"login": "bob"},
                    "createdAt": "2026-11-20T12:00:00Z",
                    "body": "\n".join(
                        [
                            pg.MARKER_START,
                            "- [PRG-001] (active) 対象: `src/ipc/**` | ルール: タイムアウトと認可チェックを常に通す | 根拠: commit `bbb2222`",
                            pg.MARKER_END,
                        ]
                    ),
                },
                {
                    "id": "IC_OLD",
                    "author": {"login": "alice"},
                    "createdAt": "2026-11-20T09:00:00Z",
                    "body": "\n".join(
                        [
                            pg.MARKER_START,
                            "- [PRG-001] (active) 対象: `src/ipc/**` | ルール: 初期案 | 根拠: commit `aaa1111`",
                            pg.MARKER_END,
                        ]
                    ),
                },
            ]
        }
        with tempfile.TemporaryDirectory() as tmp:
            in_path = _write_json(Path(tmp) / "pr.json", pr_data)
            code, out, err = _run_cli(["extract", "--input", in_path, "--format", "json"])
        self.assertEqual(code, 0, err)
        payload = json.loads(out)
        self.assertEqual(payload["active_count"], 1)
        self.assertEqual(payload["active"][0]["rule"], "タイムアウトと認可チェックを常に通す")
        self.assertEqual(payload["active"][0]["source"]["comment_id"], "IC_NEW")

    def test_prg_ut_03_retired_excludes_active_and_keeps_next_id(self) -> None:
        """PRG-UT-03: 後続コメントの (retired) で項目が有効一覧から除外され、欠番 ID を再利用しない。"""
        pr_data = {
            "comments": [
                {
                    "id": "IC_1",
                    "createdAt": "2026-11-20T10:00:00Z",
                    "body": "\n".join(
                        [
                            pg.MARKER_START,
                            "- [PRG-001] (active) 対象: `a.py` | ルール: ルール1",
                            "- [PRG-002] (active) 対象: `b.py` | ルール: ルール2",
                            pg.MARKER_END,
                        ]
                    ),
                },
                {
                    "id": "IC_2",
                    "createdAt": "2026-11-20T11:00:00Z",
                    "body": "\n".join(
                        [
                            pg.MARKER_START,
                            "- [PRG-002] (retired) 理由: ラッパー統合で不要化",
                            pg.MARKER_END,
                        ]
                    ),
                },
            ]
        }
        with tempfile.TemporaryDirectory() as tmp:
            in_path = _write_json(Path(tmp) / "pr.json", pr_data)
            code, out, err = _run_cli(
                ["extract", "--input", in_path, "--format", "json", "--include-retired"]
            )
        self.assertEqual(code, 0, err)
        payload = json.loads(out)
        self.assertEqual(payload["active_count"], 1)
        self.assertEqual(payload["retired_count"], 1)
        self.assertEqual(payload["next_id"], "PRG-003")
        self.assertEqual([i["id"] for i in payload["active"]], ["PRG-001"])
        self.assertEqual(payload["retired"][0]["id"], "PRG-002")
        self.assertEqual(payload["retired"][0]["reason"], "ラッパー統合で不要化")

    def test_prg_ut_04_details_and_fullwidth_colon(self) -> None:
        """PRG-UT-04: <details> 折りたたみ内包ブロックおよび全角コロン表記を正しく抽出できる。"""
        pr_data = {
            "comments": [
                {
                    "id": "IC_1",
                    "createdAt": "2026-11-20T10:00:00Z",
                    "body": "\n".join(
                        [
                            pg.MARKER_START,
                            "<details>",
                            "<summary>再発防止策（PR 内引き継ぎ）</summary>",
                            "",
                            "- [PRG-001] 対象：`src/db/**` | ルール：トランザクション境界で rollback 漏れを防ぐ | 根拠：commit `c1`",
                            "",
                            "</details>",
                            pg.MARKER_END,
                        ]
                    ),
                }
            ]
        }
        with tempfile.TemporaryDirectory() as tmp:
            in_path = _write_json(Path(tmp) / "pr.json", pr_data)
            code, out, err = _run_cli(["extract", "--input", in_path, "--format", "json"])
        self.assertEqual(code, 0, err)
        payload = json.loads(out)
        self.assertEqual(payload["warnings"], [])
        self.assertEqual(payload["active_count"], 1)
        self.assertEqual(payload["active"][0]["scope"], "`src/db/**`")
        self.assertEqual(payload["active"][0]["rule"], "トランザクション境界で rollback 漏れを防ぐ")
        self.assertEqual(payload["active"][0]["evidence"], "commit `c1`")

    def test_prg_ut_05_ignore_fenced_example_markers(self) -> None:
        """PRG-UT-05: フェンス付きコードブロック（``` と ~~~）内の例示マーカーを誤抽出しない。"""
        pr_data = {
            "comments": [
                {
                    "id": "IC_1",
                    "createdAt": "2026-11-20T10:00:00Z",
                    "body": "\n".join(
                        [
                            "```markdown",
                            pg.MARKER_START,
                            "- [PRG-999] (active) 対象: `fake` | ルール: 偽項目1",
                            pg.MARKER_END,
                            "```",
                            "~~~md",
                            pg.MARKER_START,
                            "- [PRG-998] (active) 対象: `fake2` | ルール: 偽項目2",
                            pg.MARKER_END,
                            "~~~",
                            pg.MARKER_START,
                            "- [PRG-001] (active) 対象: `real.py` | ルール: 本物の制約",
                            pg.MARKER_END,
                        ]
                    ),
                }
            ]
        }
        with tempfile.TemporaryDirectory() as tmp:
            in_path = _write_json(Path(tmp) / "pr.json", pr_data)
            code, out, err = _run_cli(["extract", "--input", in_path, "--format", "json"])
        self.assertEqual(code, 0, err)
        payload = json.loads(out)
        self.assertEqual(payload["active_count"], 1)
        self.assertEqual(payload["active"][0]["id"], "PRG-001")
        self.assertEqual(payload["next_id"], "PRG-002")

    def test_prg_ut_06_pipes_inside_rule_text_not_split(self) -> None:
        """PRG-UT-06: ルール本文に a || b や x | y を含んでもフィールドが誤分割されない。"""
        pr_data = {
            "comments": [
                {
                    "id": "IC_1",
                    "createdAt": "2026-11-20T10:00:00Z",
                    "body": "\n".join(
                        [
                            pg.MARKER_START,
                            "- [PRG-001] (active) 対象: `src/parser.ts` | ルール: `a || b` や `x | y` の短絡評価順を維持する | 根拠: commit `d4`",
                            pg.MARKER_END,
                        ]
                    ),
                }
            ]
        }
        with tempfile.TemporaryDirectory() as tmp:
            in_path = _write_json(Path(tmp) / "pr.json", pr_data)
            code, out, err = _run_cli(["extract", "--input", in_path, "--format", "json"])
        self.assertEqual(code, 0, err)
        payload = json.loads(out)
        self.assertEqual(payload["warnings"], [])
        self.assertEqual(
            payload["active"][0]["rule"],
            "`a || b` や `x | y` の短絡評価順を維持する",
        )
        self.assertEqual(payload["active"][0]["evidence"], "commit `d4`")

    def test_prg_ut_07_pr_body_as_base_overridden_by_comments(self) -> None:
        """PRG-UT-07: PR 本文 body と comments の両方にブロックがある場合、body を基底として comments が上書きする。"""
        pr_data = {
            "id": "PR_1",
            "author": {"login": "owner"},
            "body": "\n".join(
                [
                    pg.MARKER_START,
                    "- [PRG-001] (active) 対象: `a.py` | ルール: 本文初期ルール",
                    "- [PRG-002] (active) 対象: `b.py` | ルール: 本文残存ルール",
                    pg.MARKER_END,
                ]
            ),
            "comments": [
                {
                    "id": "IC_1",
                    "author": {"login": "reviewer"},
                    "createdAt": "2026-11-20T09:00:00Z",
                    "body": "\n".join(
                        [
                            pg.MARKER_START,
                            "- [PRG-001] (active) 対象: `a.py` | ルール: コメント改訂ルール",
                            pg.MARKER_END,
                        ]
                    ),
                }
            ],
        }
        with tempfile.TemporaryDirectory() as tmp:
            in_path = _write_json(Path(tmp) / "pr.json", pr_data)
            code, out, err = _run_cli(["extract", "--input", in_path, "--format", "json"])
        self.assertEqual(code, 0, err)
        payload = json.loads(out)
        self.assertEqual(payload["active_count"], 2)
        self.assertEqual(payload["active"][0]["rule"], "コメント改訂ルール")
        self.assertEqual(payload["active"][1]["rule"], "本文残存ルール")

    def test_prg_ut_08_graphql_and_plain_array_formats(self) -> None:
        """PRG-UT-08: GraphQL pullRequest.comments.nodes 形式およびプレーンコメント配列 JSON を解釈できる。"""
        graphql_data = {
            "data": {
                "repository": {
                    "pullRequest": {
                        "body": "",
                        "comments": {
                            "nodes": [
                                {
                                    "id": "IC_G1",
                                    "author": {"login": "alice"},
                                    "createdAt": "2026-11-20T10:00:00Z",
                                    "body": f"{pg.MARKER_START}\n- [PRG-001] (active) 対象: `g.py` | ルール: GraphQL 抽出\n{pg.MARKER_END}",
                                }
                            ]
                        },
                    }
                }
            }
        }
        plain_array = [
            {
                "id": "IC_A1",
                "user": {"login": "bob"},
                "created_at": "2026-11-20T10:00:00Z",
                "body": f"{pg.MARKER_START}\n- [PRG-001] (active) 対象: `a.py` | ルール: 配列抽出\n{pg.MARKER_END}",
            }
        ]
        with tempfile.TemporaryDirectory() as tmp:
            g_path = _write_json(Path(tmp) / "graphql.json", graphql_data)
            a_path = _write_json(Path(tmp) / "array.json", plain_array)
            c1, o1, e1 = _run_cli(["extract", "--input", g_path, "--format", "json"])
            c2, o2, e2 = _run_cli(["extract", "--input", a_path, "--format", "json"])
        self.assertEqual(c1, 0, e1)
        self.assertEqual(c2, 0, e2)
        self.assertEqual(json.loads(o1)["active"][0]["rule"], "GraphQL 抽出")
        self.assertEqual(json.loads(o2)["active"][0]["rule"], "配列抽出")

    def test_prg_ut_09_author_filter(self) -> None:
        """PRG-UT-09: --author フィルタで指定投稿者以外のコメントを除外できる。"""
        pr_data = {
            "comments": [
                {
                    "id": "IC_1",
                    "author": {"login": "TrustedBot"},
                    "createdAt": "2026-11-20T10:00:00Z",
                    "body": f"{pg.MARKER_START}\n- [PRG-001] (active) 対象: `a.py` | ルール: 信頼済みルール\n{pg.MARKER_END}",
                },
                {
                    "id": "IC_2",
                    "author": {"login": "untrusted"},
                    "createdAt": "2026-11-20T11:00:00Z",
                    "body": f"{pg.MARKER_START}\n- [PRG-001] (active) 対象: `a.py` | ルール: 上書きすべきでない\n{pg.MARKER_END}",
                },
            ]
        }
        with tempfile.TemporaryDirectory() as tmp:
            in_path = _write_json(Path(tmp) / "pr.json", pr_data)
            code, out, err = _run_cli(
                ["extract", "--input", in_path, "--author", "trustedbot", "--format", "json"]
            )
        self.assertEqual(code, 0, err)
        payload = json.loads(out)
        self.assertEqual(payload["active_count"], 1)
        self.assertEqual(payload["active"][0]["rule"], "信頼済みルール")

    def test_prg_ut_10_empty_pr_returns_zero(self) -> None:
        """PRG-UT-10: マーカーが存在しない PR JSON で終了コード 0、active_count == 0 となる。"""
        pr_data = {"body": "通常の PR 説明", "comments": [{"body": "LGTM"}]}
        with tempfile.TemporaryDirectory() as tmp:
            in_path = _write_json(Path(tmp) / "pr.json", pr_data)
            code, out, err = _run_cli(["extract", "--input", in_path, "--format", "json"])
        self.assertEqual(code, 0, err)
        payload = json.loads(out)
        self.assertEqual(payload["active_count"], 0)
        self.assertEqual(payload["retired_count"], 0)
        self.assertEqual(payload["next_id"], "PRG-001")

    def test_prg_ut_11_rules_md_integrates_with_invariant_gate(self) -> None:
        """PRG-UT-11: extract --format rules-md の出力を invariant-gate で解析し、有効項目と 1 対 1 で RuleItem が生成される。"""
        pr_data = {
            "comments": [
                {
                    "id": "IC_1",
                    "createdAt": "2026-11-20T10:00:00Z",
                    "body": "\n".join(
                        [
                            pg.MARKER_START,
                            "- [PRG-001] (active) 対象: `src/a.py` | ルール: 例外を握りつぶさない | 根拠: commit `111`",
                            "- [PRG-002] (active) 対象: `src/b.py` | ルール: タイムアウト値を設定する",
                            "- [PRG-003] (retired) 理由: 不要化",
                            pg.MARKER_END,
                        ]
                    ),
                }
            ]
        }
        with tempfile.TemporaryDirectory() as tmp:
            in_path = _write_json(Path(tmp) / "pr.json", pr_data)
            md_path = Path(tmp) / "guardrails.md"
            code, _, err = _run_cli(
                ["extract", "--input", in_path, "--format", "rules-md", "--output", str(md_path)]
            )
            self.assertEqual(code, 0, err)
            md_text = md_path.read_text(encoding="utf-8")
        rules = cid.extract_rules_from_markdown(md_text, "guardrails.md")
        self.assertEqual(len(rules), 2)
        self.assertTrue(any("PRG-001" in r.text and "例外を握りつぶさない" in r.text for r in rules))
        self.assertTrue(any("PRG-002" in r.text and "タイムアウト値を設定する" in r.text for r in rules))
        self.assertFalse(any("PRG-003" in r.text for r in rules))

    def test_prg_ut_12_empty_rules_md_yields_zero_rule_items(self) -> None:
        """PRG-UT-12: 有効項目 0 件の rules-md 出力が extract_rules_from_markdown() で 0 件になる。"""
        pr_data = {
            "comments": [
                {
                    "id": "IC_1",
                    "createdAt": "2026-11-20T10:00:00Z",
                    "body": f"{pg.MARKER_START}\n- [PRG-001] (retired) 理由: 失効のみ\n{pg.MARKER_END}",
                }
            ]
        }
        with tempfile.TemporaryDirectory() as tmp:
            in_path = _write_json(Path(tmp) / "pr.json", pr_data)
            code, out, err = _run_cli(["extract", "--input", in_path, "--format", "rules-md"])
        self.assertEqual(code, 0, err)
        rules = cid.extract_rules_from_markdown(out, "guardrails.md")
        self.assertEqual(rules, [])

    def test_prg_ut_13_brief_format_excludes_retired(self) -> None:
        """PRG-UT-13: extract --format brief が有効項目と矛盾時優先ルールを出力し、retired 項目を含まない。"""
        pr_data = {
            "comments": [
                {
                    "id": "IC_1",
                    "createdAt": "2026-11-20T10:00:00Z",
                    "body": "\n".join(
                        [
                            pg.MARKER_START,
                            "- [PRG-001] (active) 対象: `api.py` | ルール: 入力バリデーションを省略しない",
                            "- [PRG-002] (retired) 理由: 廃止済み項目",
                            pg.MARKER_END,
                        ]
                    ),
                }
            ]
        }
        with tempfile.TemporaryDirectory() as tmp:
            in_path = _write_json(Path(tmp) / "pr.json", pr_data)
            code, out, err = _run_cli(["extract", "--input", in_path, "--format", "brief"])
        self.assertEqual(code, 0, err)
        self.assertIn("PRG-001", out)
        self.assertIn("実物とユーザー確認を優先", out)
        self.assertNotIn("PRG-002", out)

    def test_prg_ut_14_render_and_roundtrip(self) -> None:
        """PRG-UT-14: render が新規自動採番、--existing 連動採番、retired、--collapsible を生成し extract と往復一致する。"""
        existing_pr = {
            "comments": [
                {
                    "id": "IC_1",
                    "createdAt": "2026-11-20T09:00:00Z",
                    "body": f"{pg.MARKER_START}\n- [PRG-001] (active) 対象: `old.py` | ルール: 旧ルール\n{pg.MARKER_END}",
                }
            ]
        }
        new_items = [
            {"scope": "src/new.py", "rule": "新規制約を追加する", "evidence": "commit abc123"},
            {"id": "PRG-001", "status": "retired", "reason": "統合済みのため不要"},
        ]
        with tempfile.TemporaryDirectory() as tmp:
            ex_path = _write_json(Path(tmp) / "existing.json", existing_pr)
            items_path = _write_json(Path(tmp) / "items.json", new_items)
            code, rendered, err = _run_cli(
                ["render", "--items", items_path, "--existing", ex_path, "--collapsible"]
            )
            self.assertEqual(code, 0, err)
            self.assertIn("<details>", rendered)
            self.assertIn("[PRG-002] (active)", rendered)
            self.assertIn("[PRG-001] (retired)", rendered)

            combined_pr = {
                "comments": [
                    *existing_pr["comments"],
                    {"id": "IC_2", "createdAt": "2026-11-20T12:00:00Z", "body": rendered},
                ]
            }
            comb_path = _write_json(Path(tmp) / "combined.json", combined_pr)
            c2, out2, e2 = _run_cli(
                ["extract", "--input", comb_path, "--format", "json", "--include-retired"]
            )
        self.assertEqual(c2, 0, e2)
        payload = json.loads(out2)
        self.assertEqual(payload["active_count"], 1)
        self.assertEqual(payload["retired_count"], 1)
        self.assertEqual(payload["active"][0]["id"], "PRG-002")
        self.assertEqual(payload["active"][0]["rule"], "新規制約を追加する")
        self.assertEqual(payload["retired"][0]["id"], "PRG-001")
        self.assertEqual(payload["next_id"], "PRG-003")

    def test_prg_ut_15_env_path_blocked_and_example_allowed(self) -> None:
        """PRG-UT-15: .env 系パス指定時に終了コード 2 で遮断される（.env.example は許容）。"""
        with tempfile.TemporaryDirectory() as tmp:
            env_example = Path(tmp) / ".env.example"
            _write_json(env_example, {"comments": []})
            c_ok, _, err_ok = _run_cli(["extract", "--input", str(env_example)])
            c_blk1, _, err_blk1 = _run_cli(["extract", "--input", str(Path(tmp) / ".env")])
            c_blk2, _, err_blk2 = _run_cli(["extract", "--input", str(env_example), "--output", str(Path(tmp) / ".env.local")])
        self.assertEqual(c_ok, 0, err_ok)
        self.assertEqual(c_blk1, 2)
        self.assertIn(".env", err_blk1)
        self.assertEqual(c_blk2, 2)
        self.assertIn(".env", err_blk2)

    def test_prg_ut_16_secrets_blocked_without_exposing_raw_value(self) -> None:
        """PRG-UT-16: GitHub トークンや API キー混入時に extract と render が終了コード 2 で遮断し、実値を露出しない。"""
        fake_ghp = "ghp_" + "AbCdEfGhIjKlMnOpQrStUvWxYz123456"
        fake_aiza = "AIza" + "SyTestSecretValue1234567890abcd"
        pr_data = {
            "comments": [
                {
                    "id": "IC_1",
                    "createdAt": "2026-11-20T10:00:00Z",
                    "body": f"{pg.MARKER_START}\n- [PRG-001] (active) 対象: `cfg` | ルール: {fake_ghp} を使うな\n{pg.MARKER_END}",
                }
            ]
        }
        items_data = [{"scope": "cfg", "rule": f"キー {fake_aiza} を直書きしない"}]
        with tempfile.TemporaryDirectory() as tmp:
            pr_path = _write_json(Path(tmp) / "pr.json", pr_data)
            items_path = _write_json(Path(tmp) / "items.json", items_data)
            c1, o1, e1 = _run_cli(["extract", "--input", pr_path])
            c2, o2, e2 = _run_cli(["render", "--items", items_path])
        self.assertEqual(c1, 2)
        self.assertEqual(o1, "")
        self.assertNotIn(fake_ghp, e1)
        self.assertEqual(c2, 2)
        self.assertEqual(o2, "")
        self.assertNotIn(fake_aiza, e2)

    def test_prg_ut_17_render_rejects_invalid_inputs(self) -> None:
        """PRG-UT-17: render 入力の U+FFFD、埋め込み改行、重複 ID、retired の ID 欠落を終了コード 2 で拒否する。"""
        bad_cases = [
            [{"rule": "文字化け\ufffdあり"}],
            [{"rule": "1行目\n2行目"}],
            [{"id": "PRG-001", "rule": "A"}, {"id": "PRG-001", "rule": "B"}],
            [{"status": "retired", "reason": "ID なし"}],
        ]
        with tempfile.TemporaryDirectory() as tmp:
            for idx, items in enumerate(bad_cases):
                items_path = _write_json(Path(tmp) / f"bad_{idx}.json", items)
                code, _, _ = _run_cli(["render", "--items", items_path])
                self.assertEqual(code, 2, f"case {idx} should fail with exit 2")

    def test_prg_ut_18_strict_mode_catches_malformed_or_fffd(self) -> None:
        """PRG-UT-18: extract --strict がブロック内不正行や U+FFFD 混入を終了コード 2 で検出し、通常モードは警告付き終了コード 0 となる。"""
        pr_data = {
            "comments": [
                {
                    "id": "IC_1",
                    "createdAt": "2026-11-20T10:00:00Z",
                    "body": "\n".join(
                        [
                            pg.MARKER_START,
                            "- [PRG-001] (active) 対象: `a.py` | ルール: 正常項目\ufffd",
                            "- 書式不正な行",
                            pg.MARKER_END,
                        ]
                    ),
                }
            ]
        }
        with tempfile.TemporaryDirectory() as tmp:
            pr_path = _write_json(Path(tmp) / "pr.json", pr_data)
            c_norm, o_norm, _ = _run_cli(["extract", "--input", pr_path, "--format", "json"])
            c_strict, _, e_strict = _run_cli(["extract", "--input", pr_path, "--strict"])
        self.assertEqual(c_norm, 0)
        payload = json.loads(o_norm)
        self.assertGreaterEqual(len(payload["warnings"]), 2)
        self.assertEqual(c_strict, 2)
        self.assertIn("[ERROR]", e_strict)


if __name__ == "__main__":
    unittest.main()
