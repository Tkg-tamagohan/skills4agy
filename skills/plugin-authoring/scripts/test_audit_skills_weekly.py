#!/usr/bin/env python3
"""audit_skills_weekly.py の単体テスト。"""

from __future__ import annotations

from contextlib import redirect_stdout
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

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import audit_skills_weekly as asw  # noqa: E402


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _build_fixture_repo(repo: Path) -> None:
    """各種検出観点を網羅する最小フィクスチャリポジトリを構築する。"""
    _write_text(
        repo / "rules" / "AGENTS.md",
        "# AGENTS.md\n\n## 共通規則\n\n- 推測を断定しない。\n",
    )
    _write_text(
        repo / "rules" / "alpha-rule.md",
        "---\ntrigger: model_decision\ndescription: α作業を実行するときに使用する。\n---\n\n"
        "# α規則\n\n確認する。\n\n## 手順\n\n1. `alpha-skill` に従う。\n\n## 対象外\n\nなし。\n",
    )
    _write_text(
        repo / "rules" / "dangling-rule.md",
        "---\ntrigger: model_decision\ndescription: "
        + ("ダミー説明を長く記載するとき。" * 8)
        + "\n---\n\n# 不整合規則\n\n## 手順\n\n1. `ghost-missing-skill` に委ねる。\n\n## 対象外\n\nなし。\n",
    )

    # alpha-skill: 2本のスクリプト（script_a/script_b相当）・CLI フラグ乖離・横断 import あり
    _write_text(
        repo / "skills" / "alpha-skill" / "SKILL.md",
        "---\nname: alpha-skill\n"
        "description: α処理を実行するときに使用する。共有補助は beta-helper に委ねる。\n"
        "---\n\n# αスキル\n\n## 責任範囲の境界\n\n- 詳細設定は `beta-helper` に委ねる。\n\n"
        "## 手順\n\n```powershell\n"
        "python \"$HOME/.gemini/config/plugins/shared-skills/skills/alpha-skill/scripts/run_alpha.py\" --real-flag --only-b --ghost-flag\n"
        "python \"$HOME/.gemini/config/plugins/shared-skills/skills/alpha-skill/scripts/other_alpha.py\" --only-b\n"
        "```\n",
    )
    _write_text(
        repo / "skills" / "alpha-skill" / "scripts" / "run_alpha.py",
        "import argparse\nimport shared_util\n\n"
        "def main():\n"
        "    p = argparse.ArgumentParser()\n"
        "    p.add_argument('--real-flag')\n"
        "    return 0\n",
    )
    _write_text(
        repo / "skills" / "alpha-skill" / "scripts" / "other_alpha.py",
        "import argparse\n\n"
        "def main():\n"
        "    p = argparse.ArgumentParser()\n"
        "    p.add_argument('--only-b')\n"
        "    return 0\n",
    )
    _write_text(
        repo / "skills" / "alpha-skill" / "scripts" / "test_run_alpha.py",
        "import unittest\n\nclass T(unittest.TestCase):\n"
        "    def test_one(self): pass\n"
        "    def test_two(self): pass\n",
    )

    # beta-helper: 共有モジュールを持ち、長大な description と 180 行超本文
    long_desc = "β処理の共通ガイド。" + ("テストや仕様を監査するときに使用する。" * 12)
    long_body = "\n".join(f"{i}. 手順 {i} を実行する。" for i in range(1, 185))
    _write_text(
        repo / "skills" / "beta-helper" / "SKILL.md",
        f"---\nname: beta-helper\ndescription: {long_desc}\n---\n\n# βヘルパー\n\n{long_body}\n",
    )
    _write_text(
        repo / "skills" / "beta-helper" / "scripts" / "shared_util.py",
        "VALUE = 1\n",
    )

    # manual-heavy: スクリプトなし・長手順・コードブロック多数 -> mechanization_candidate
    steps = "\n".join(f"{i}. 定型ステップ {i} を実施する。" for i in range(1, 9))
    blocks = "\n".join("```bash\necho ok\n```\n" for _ in range(3))
    _write_text(
        repo / "skills" / "manual-heavy" / "SKILL.md",
        "---\nname: manual-heavy\n"
        "description: 手動定型作業を実施するときに使用する。類似としてテストや仕様を監査するときにも使う。\n"
        "---\n\n# 手動定型作業\n\n"
        f"{steps}\n\n{blocks}\n",
    )

    _write_text(
        repo / "hooks.json",
        json.dumps(
            {
                "decision1-pretool-guard": {
                    "enabled": True,
                    "PreToolUse": [
                        {
                            "matcher": "run_command",
                            "hooks": [
                                {
                                    "type": "command",
                                    "command": "python skills/alpha-skill/scripts/run_alpha.py",
                                    "timeout": 15,
                                }
                            ],
                        }
                    ],
                }
            }
        ),
    )
    _write_text(
        repo / "REVIEW.md",
        "# Review\n\n### 除外対象（実パス）\n\n- `skills/alpha-skill/scripts/run_alpha.py`\n- `skills/missing/gone.py`\n",
    )
    _write_text(
        repo / ".sloplintignore",
        "# comment\nskills/beta-helper/SKILL.md\nskills/nonexistent/*.md\n",
    )


class TestAuditSkillsWeekly(unittest.TestCase):
    def test_usage_vs_maintenance_and_detectors(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / "dev_repo"
            prod = root / "prod_plugin"
            app = root / "app_data"
            _build_fixture_repo(repo)
            prod.mkdir(parents=True)

            s1_log = app / "brain" / "sess-0001" / ".system_generated" / "logs" / "transcript.jsonl"
            prod_skill = str(prod / "skills" / "alpha-skill" / "SKILL.md")
            prod_script = str(prod / "skills" / "alpha-skill" / "scripts" / "run_alpha.py")
            prod_rule = str(prod / "rules" / "alpha-rule.md")
            dev_skill = str(repo / "skills" / "beta-helper" / "SKILL.md")

            events_s1 = [
                {
                    "type": "PLANNER_RESPONSE",
                    "created_at": "2026-11-24T10:00:00Z",
                    "tool_calls": [
                        {
                            "name": "read_file",
                            "args": {"Path": json.dumps(prod_skill)},
                        },
                        {
                            "name": "read_file",
                            "args": {"Path": json.dumps(prod_rule)},
                        },
                        {
                            "name": "read_file",
                            "args": {"Path": json.dumps(dev_skill)},
                        },
                        {
                            "name": "run_command",
                            "args": {
                                "CommandLine": f'python "{prod_script}" --real-flag'
                            },
                        },
                    ],
                },
                {
                    "type": "GENERIC",
                    "created_at": "2026-11-24T10:01:00Z",
                    "content": asw.PRETOOL_FALLBACK_MARKER,
                },
                "{malformed json line",
            ]
            _write_text(
                s1_log,
                "\n".join(
                    e if isinstance(e, str) else json.dumps(e, ensure_ascii=False)
                    for e in events_s1
                )
                + "\n",
            )

            s2_log = app / "brain" / "sess-0002" / ".system_generated" / "logs" / "transcript.jsonl"
            events_s2 = [
                {
                    "type": "PLANNER_RESPONSE",
                    "created_at": "2026-11-12T10:00:00Z",
                    "tool_calls": [
                        {
                            "name": "read_file",
                            "args": {
                                "Path": "$HOME/.gemini/config/plugins/shared-skills/skills/manual-heavy/SKILL.md"
                            },
                        }
                    ],
                },
                {
                    "type": "PLANNER_RESPONSE",
                    "created_at": "2026-10-10T10:00:00Z",
                    "tool_calls": [
                        {
                            "name": "read_file",
                            "args": {
                                "Path": str(prod / "skills" / "beta-helper" / "SKILL.md")
                            },
                        }
                    ],
                },
            ]
            _write_text(
                s2_log,
                "\n".join(json.dumps(e, ensure_ascii=False) for e in events_s2) + "\n",
            )

            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = asw.main(
                    [
                        "--repo",
                        str(repo),
                        "--prod-root",
                        str(prod),
                        "--app-data-dir",
                        str(app),
                        "--now",
                        "2026-11-27T12:00:00Z",
                        "--no-git",
                        "--format",
                        "json",
                    ]
                )
            self.assertEqual(rc, 0)
            data = json.loads(buf.getvalue())

            self.assertEqual(data["meta"]["usage_status"], "ok")
            self.assertTrue(data["meta"]["usage_complete"])
            self.assertEqual(data["meta"]["malformed_lines"], 1)
            self.assertEqual(data["meta"]["active_sessions_7d"], 1)
            self.assertEqual(data["meta"]["active_sessions_28d"], 2)

            skills_by_name = {r["name"]: r for r in data["skills"]}
            self.assertEqual(skills_by_name["alpha-skill"]["usage_7d"], 2)
            self.assertEqual(skills_by_name["alpha-skill"]["script_runs_7d"], 1)
            self.assertEqual(skills_by_name["alpha-skill"]["test_case_count"], 2)
            # スクリプト単位で照合されるため other_alpha.py 専用の --only-b も run_alpha.py 側の乖離として検知
            self.assertEqual(
                skills_by_name["alpha-skill"]["doc_only_flags"],
                ["run_alpha.py:--ghost-flag", "run_alpha.py:--only-b"],
            )

            self.assertEqual(skills_by_name["beta-helper"]["usage_28d"], 0)
            self.assertEqual(skills_by_name["beta-helper"]["maintenance_touches_28d"], 1)
            self.assertIn("prune_or_merge_candidate", skills_by_name["beta-helper"]["tags"])
            self.assertIn("trim_description_candidate", skills_by_name["beta-helper"]["tags"])
            self.assertIn("split_body_candidate", skills_by_name["beta-helper"]["tags"])

            self.assertEqual(skills_by_name["manual-heavy"]["usage_7d"], 0)
            self.assertEqual(skills_by_name["manual-heavy"]["usage_28d"], 1)
            self.assertIn("mechanization_candidate", skills_by_name["manual-heavy"]["tags"])

            rules_by_name = {r["name"]: r for r in data["rules"]}
            self.assertEqual(rules_by_name["alpha-rule"]["usage_7d"], 1)
            self.assertEqual(rules_by_name["dangling-rule"]["usage_28d"], 0)

            dangling = data["boundaries"]["dangling_references"]
            self.assertEqual(len(dangling), 1)
            self.assertEqual(dangling[0]["target"], "ghost-missing-skill")
            self.assertTrue(data["boundaries"]["top_description_overlaps"])

            edges = data["coupling_and_hooks"]["cross_skill_imports"]
            self.assertEqual(len(edges), 1)
            self.assertEqual(edges[0]["from_skill"], "alpha-skill")
            self.assertEqual(edges[0]["to_skill"], "beta-helper")
            self.assertEqual(data["coupling_and_hooks"]["pretool_fallback_7d"], 1)
            self.assertEqual(data["coupling_and_hooks"]["pretool_fallback_28d"], 1)

            self.assertEqual(
                data["hygiene_blind_spots"]["missing_review_exclusions"],
                ["skills/missing/gone.py"],
            )
            self.assertEqual(
                data["hygiene_blind_spots"]["missing_slop_ignores"],
                ["skills/nonexistent/*.md"],
            )

            # Markdown にフック詳細、横断結合詳細、切れパス一覧、context_audit 省略理由が含まれる
            md = asw.render_markdown(data)
            self.assertIn("# 週次 SKILL 監査定量レポート", md)
            self.assertIn("`decision1-pretool-guard` enabled=True timeout=[15]", md)
            self.assertIn("`alpha-skill/run_alpha.py` -> `beta-helper` (`shared_util`)", md)
            self.assertIn("REVIEW.md 除外切れ: `skills/missing/gone.py`", md)
            self.assertIn(".sloplintignore 切れ: `skills/nonexistent/*.md`", md)
            self.assertIn("--include-context-audit 未指定", md)

    def test_unavailable_logs_do_not_mark_zero_or_prune(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / "dev_repo"
            prod = root / "prod_plugin"
            app = root / "empty_app_data"
            _build_fixture_repo(repo)
            prod.mkdir(parents=True)

            # 1. brain ディレクトリ未存在
            rep_no_brain = asw.build_weekly_report(
                repo_root=repo,
                prod_root=prod,
                app_data_dir=app,
                now_dt=asw.parse_iso_datetime("2026-11-27T12:00:00Z"),
                days=7,
                window_days=28,
                use_git=False,
                include_context_audit=False,
            )
            self.assertEqual(rep_no_brain["meta"]["usage_status"], "unavailable_no_brain_dir")
            self.assertFalse(rep_no_brain["meta"]["usage_complete"])
            self.assertTrue(rep_no_brain["inventory_candidates"]["usage_based_pruning_skipped"])
            self.assertEqual(rep_no_brain["inventory_candidates"]["prune_or_merge_candidates"], [])
            self.assertEqual(rep_no_brain["inventory_candidates"]["zero_usage_28d_skills"], [])
            for r in rep_no_brain["skills"]:
                self.assertIsNone(r["usage_28d"])
                self.assertNotIn("prune_or_merge_candidate", r["tags"])
            md = asw.render_markdown(rep_no_brain)
            self.assertIn("unavailable_no_brain_dir", md)
            self.assertIn("判定省略", md)

            # 2. brain ディレクトリありだがトランスクリプト 0 件
            (app / "brain").mkdir(parents=True)
            rep_empty = asw.build_weekly_report(
                repo_root=repo,
                prod_root=prod,
                app_data_dir=app,
                now_dt=asw.parse_iso_datetime("2026-11-27T12:00:00Z"),
                days=7,
                window_days=28,
                use_git=False,
                include_context_audit=False,
            )
            self.assertEqual(rep_empty["meta"]["usage_status"], "unavailable_no_transcripts")
            self.assertEqual(rep_empty["inventory_candidates"]["prune_or_merge_candidates"], [])

            # 3. 読込失敗ファイルがある場合 (partial_read_errors) も統廃合候補に入れない
            s_dir = app / "brain" / "sess-bad" / ".system_generated" / "logs"
            s_dir.mkdir(parents=True)
            (s_dir / "transcript.jsonl").mkdir()  # ファイルではなくディレクトリにして OSError を誘発
            rep_partial = asw.build_weekly_report(
                repo_root=repo,
                prod_root=prod,
                app_data_dir=app,
                now_dt=asw.parse_iso_datetime("2026-11-27T12:00:00Z"),
                days=7,
                window_days=28,
                use_git=False,
                include_context_audit=False,
            )
            self.assertEqual(rep_partial["meta"]["usage_status"], "partial_read_errors")
            self.assertFalse(rep_partial["meta"]["usage_complete"])
            self.assertEqual(rep_partial["meta"]["unreadable_transcripts"], 1)
            self.assertEqual(rep_partial["inventory_candidates"]["prune_or_merge_candidates"], [])

    def test_run_command_position_and_cwd_resolution(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / "dev_repo"
            prod = root / "prod_plugin"
            other = root / "other_dir"
            app = root / "app_data"
            _build_fixture_repo(repo)
            prod.mkdir(parents=True)
            other.mkdir(parents=True)

            prod_script = str(prod / "skills" / "alpha-skill" / "scripts" / "run_alpha.py")
            s_log = app / "brain" / "sess-cmd" / ".system_generated" / "logs" / "transcript.jsonl"
            events = [
                {
                    "type": "PLANNER_RESPONSE",
                    "created_at": "2026-11-25T10:00:00Z",
                    "tool_calls": [
                        # 非 python コマンドの引数・閲覧・差分確認は計上しない
                        {"name": "run_command", "args": {"CommandLine": f'git diff -- "{prod_script}"'}},
                        {"name": "run_command", "args": {"CommandLine": f'rg foo "{prod_script}"'}},
                        {"name": "run_command", "args": {"CommandLine": f'python -c "print(\'{prod_script}\')"'}},
                        # 相対パス + Cwd=other -> 対象外
                        {"name": "run_command", "args": {"CommandLine": "python skills/alpha-skill/scripts/run_alpha.py", "Cwd": str(other)}},
                        # 相対パス + Cwd=repo -> maintenance (+1)
                        {"name": "run_command", "args": {"CommandLine": "python skills/alpha-skill/scripts/run_alpha.py", "Cwd": str(repo)}},
                        # 相対パス + Cwd=prod -> usage (+1)
                        {"name": "run_command", "args": {"CommandLine": "python -B skills/alpha-skill/scripts/run_alpha.py", "Cwd": str(prod)}},
                        # Set-Location で prod に移動して相対実行 -> usage (+1)
                        {"name": "run_command", "args": {"CommandLine": f'Set-Location "{prod}"; python skills/alpha-skill/scripts/other_alpha.py --only-b', "Cwd": str(other)}},
                    ],
                }
            ]
            _write_text(s_log, "\n".join(json.dumps(e, ensure_ascii=False) for e in events) + "\n")

            rep = asw.build_weekly_report(
                repo_root=repo,
                prod_root=prod,
                app_data_dir=app,
                now_dt=asw.parse_iso_datetime("2026-11-27T12:00:00Z"),
                days=7,
                window_days=28,
                use_git=False,
                include_context_audit=False,
            )
            alpha = {r["name"]: r for r in rep["skills"]}["alpha-skill"]
            self.assertEqual(alpha["script_runs_7d"], 2)
            self.assertEqual(alpha["maintenance_touches_28d"], 1)

    def test_powershell_trailing_backslash_and_posix_quotes(self) -> None:
        """PowerShell で末尾 \\ を含む引用パス付き Set-Location 後も計上され、POSIX の \\" も誤分割されない。"""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / "dev_repo"
            prod = root / "prod_plugin"
            app = root / "app_data"
            _build_fixture_repo(repo)
            prod.mkdir(parents=True)

            # 末尾バックスラッシュ付きの Windows 形式文字列（os.name 非依存で PowerShell 判定を検証）
            repo_bs = str(repo).rstrip("\\/") + "\\"
            prod_bs = str(prod).rstrip("\\/") + "\\"
            s_log = app / "brain" / "sess-ps-bs" / ".system_generated" / "logs" / "transcript.jsonl"
            events = [
                {
                    "type": "PLANNER_RESPONSE",
                    "created_at": "2026-11-26T10:00:00Z",
                    "tool_calls": [
                        {
                            "name": "run_command",
                            "args": {
                                "CommandLine": f'Set-Location "{repo_bs}"; python -B skills/alpha-skill/scripts/run_alpha.py',
                                "Cwd": str(root),
                            },
                        },
                        {
                            "name": "run_command",
                            "args": {
                                "CommandLine": f'Set-Location "{prod_bs}"; python -B skills/alpha-skill/scripts/run_alpha.py',
                                "Cwd": str(root),
                            },
                        },
                    ],
                }
            ]
            _write_text(s_log, "\n".join(json.dumps(e, ensure_ascii=False) for e in events) + "\n")

            rep = asw.build_weekly_report(
                repo_root=repo,
                prod_root=prod,
                app_data_dir=app,
                now_dt=asw.parse_iso_datetime("2026-11-27T12:00:00Z"),
                days=7,
                window_days=28,
                use_git=False,
                include_context_audit=False,
            )
            alpha = {r["name"]: r for r in rep["skills"]}["alpha-skill"]
            self.assertEqual(alpha["script_runs_7d"], 1)
            self.assertEqual(alpha["maintenance_touches_28d"], 1)

            # POSIX シェル（Cwd が / 始まり）では二重引用符内の \" をエスケープとして扱う
            posix_cmd = 'cd "/opt/prod_plugin" && python -B skills/alpha-skill/scripts/run_alpha.py --msg "a \\"quoted; &&\\" b"'
            extracted = asw._extract_executed_python_scripts(
                posix_cmd,
                initial_cwd="/tmp/other",
                allow_unresolved_relative=False,
            )
            self.assertEqual(extracted, ["/opt/prod_plugin/skills/alpha-skill/scripts/run_alpha.py"])
            segs = asw._split_shell_segments(posix_cmd, powershell=False)
            self.assertEqual(len(segs), 2)
            toks = asw._tokenize_segment(segs[1], powershell=False)
            self.assertEqual(toks[-1], 'a "quoted; &&" b')

    def test_repo_alias_matches_maintenance_when_resolve_differs(self) -> None:
        """Windows 8.3 短縮名のように入力パスと resolve() 後が異なる場合でも保守作業として計上される。"""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            real_repo = root / "long_directory_name_repo"
            alias_repo = root / "SHORT~1"
            prod = root / "prod"
            app = root / "app"
            _build_fixture_repo(real_repo)
            prod.mkdir(parents=True)

            s_log = app / "brain" / "sess-alias" / ".system_generated" / "logs" / "transcript.jsonl"
            _write_text(
                s_log,
                json.dumps(
                    {
                        "type": "PLANNER_RESPONSE",
                        "created_at": "2026-11-25T10:00:00Z",
                        "tool_calls": [
                            {
                                "name": "read_file",
                                "args": {"Path": str(alias_repo / "skills" / "beta-helper" / "SKILL.md")},
                            }
                        ],
                    },
                    ensure_ascii=False,
                )
                + "\n",
            )

            rep = asw.build_weekly_report(
                repo_root=real_repo.resolve(),
                prod_root=prod,
                app_data_dir=app,
                now_dt=asw.parse_iso_datetime("2026-11-27T12:00:00Z"),
                days=7,
                window_days=28,
                use_git=False,
                include_context_audit=False,
                repo_root_aliases=(alias_repo,),
            )
            beta = {r["name"]: r for r in rep["skills"]}["beta-helper"]
            self.assertEqual(beta["maintenance_touches_28d"], 1)

    def test_context_audit_until_boundary_and_trusted_script_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            untrusted_repo = root / "untrusted_repo"
            prod = root / "prod"
            app = root / "app"
            _build_fixture_repo(untrusted_repo)
            prod.mkdir(parents=True)

            # 1. 悪意ある --repo 配下の偽 audit_context_metrics.py は実行されないこと
            marker = root / "pwned.txt"
            _write_text(
                untrusted_repo / "skills" / "session-context-audit" / "scripts" / "audit_context_metrics.py",
                f"from pathlib import Path\nPath({str(marker)!r}).write_text('pwned', encoding='utf-8')\n",
            )

            # 2. 実信頼パス側（本プラグイン実体）のテスト用に、一時ログで半開区間境界 [cutoff, now_dt) を検証
            #    2026-11-26T12:00:00Z (in after), 2026-11-27T12:00:00Z (== now_dt: 除外), 2026-11-28T00:00:00Z (> now_dt: 除外)
            for sid, ts in (
                ("sess-before", "2026-11-18T12:00:00Z"),
                ("sess-after", "2026-11-26T12:00:00Z"),
                ("sess-at-now", "2026-11-27T12:00:00Z"),
                ("sess-future", "2026-11-28T00:00:00Z"),
            ):
                p = app / "brain" / sid / ".system_generated" / "logs" / "transcript.jsonl"
                ev = [
                    {"type": "USER_INPUT", "created_at": ts, "content": "check"},
                    {
                        "type": "PLANNER_RESPONSE",
                        "created_at": ts,
                        "input_tokens": 100,
                        "cache_read_tokens": 900,
                        "output_tokens": 10,
                        "model": "gemini-test",
                        "tool_calls": [
                            {"name": "read_file", "args": {"Path": str(prod / "skills" / "alpha-skill" / "SKILL.md")}}
                        ],
                    },
                ]
                _write_text(p, "\n".join(json.dumps(x) for x in ev) + "\n")

            rep = asw.build_weekly_report(
                repo_root=untrusted_repo,
                prod_root=prod,
                app_data_dir=app,
                now_dt=asw.parse_iso_datetime("2026-11-27T12:00:00Z"),
                days=7,
                window_days=28,
                use_git=False,
                include_context_audit=True,
            )
            self.assertFalse(marker.exists(), "未信頼 --repo のスクリプトが実行されてはいけません")
            ca = rep["context_audit"]
            self.assertEqual(ca["status"], "ok")
            self.assertEqual(ca["before_sessions"], 1)
            self.assertEqual(ca["after_sessions"], 1)
            alpha = {r["name"]: r for r in rep["skills"]}["alpha-skill"]
            # sess-after (7d/28d) と sess-before (28d) のみ計上。sess-at-now と sess-future は除外。
            self.assertEqual(alpha["usage_7d"], 1)
            self.assertEqual(alpha["usage_28d"], 2)

            # 3. 信頼スクリプト側を偽の外部へ差し替えようとしても拒否されること
            fake_trusted = root / "fake_trusted"
            _write_text(fake_trusted / "skills" / "session-context-audit" / "scripts" / "audit_context_metrics.py", "print('{}')\n")
            with mock.patch.object(asw, "_is_reparse_or_symlink", return_value=True):
                res = asw.run_context_audit_summary(
                    app,
                    now_dt=asw.parse_iso_datetime("2026-11-27T12:00:00Z"),
                    days=7,
                    trusted_plugin_root=fake_trusted,
                )
            self.assertEqual(res["status"], "error")
            self.assertEqual(res["error"], "untrusted_context_audit_script_path")

            # Markdown に失敗理由が出ることも確認
            rep_err = dict(rep, context_audit=res)
            self.assertIn("untrusted_context_audit_script_path", asw.render_markdown(rep_err))

    def test_no_pycache_written_and_git_no_optional_locks(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            copied_scripts = root / "skills" / "plugin-authoring" / "scripts"
            copied_scripts.mkdir(parents=True)
            shutil.copy2(SCRIPT_DIR / "audit_skills_weekly.py", copied_scripts / "audit_skills_weekly.py")
            shutil.copy2(SCRIPT_DIR / "check_plugin.py", copied_scripts / "check_plugin.py")
            _build_fixture_repo(root)

            env = os.environ.copy()
            env.pop("PYTHONDONTWRITEBYTECODE", None)
            env["PYTHONUTF8"] = "1"
            # -B を付けずに実行しても __pycache__ を生成しないこと
            proc = subprocess.run(
                [
                    sys.executable,
                    str(copied_scripts / "audit_skills_weekly.py"),
                    "--repo",
                    str(root),
                    "--prod-root",
                    str(root / "prod_empty"),
                    "--app-data-dir",
                    str(root / "app_empty"),
                    "--no-git",
                    "--format",
                    "json",
                ],
                env=env,
                capture_output=True,
                text=True,
                encoding="utf-8",
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertFalse((copied_scripts / "__pycache__").exists())

            with mock.patch.object(asw.subprocess, "run") as mock_run:
                mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
                asw._run_git(root, "status", "--porcelain")
                called_cmd = mock_run.call_args[0][0]
                called_env = mock_run.call_args[1]["env"]
                self.assertIn("--no-optional-locks", called_cmd)
                self.assertEqual(called_env.get("GIT_OPTIONAL_LOCKS"), "0")

    def test_git_sync_mismatch_and_merged_branches(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            origin = root / "origin.git"
            repo = root / "repo"
            prod = root / "prod"

            def run_git(cwd: Path, *args: str) -> None:
                subprocess.run(
                    ["git", "-C", str(cwd), *args],
                    check=True,
                    capture_output=True,
                    text=True,
                )

            subprocess.run(["git", "init", "--bare", str(origin)], check=True, capture_output=True)
            subprocess.run(["git", "clone", str(origin), str(repo)], check=True, capture_output=True)
            run_git(repo, "config", "user.email", "test@example.com")
            run_git(repo, "config", "user.name", "Tester")
            run_git(repo, "checkout", "-b", "main")
            _build_fixture_repo(repo)
            run_git(repo, "add", ".")
            run_git(repo, "commit", "-m", "init")
            run_git(repo, "push", "-u", "origin", "main")

            subprocess.run(["git", "clone", str(origin), str(prod)], check=True, capture_output=True)
            run_git(prod, "config", "user.email", "test@example.com")
            run_git(prod, "config", "user.name", "Tester")

            run_git(repo, "checkout", "-b", "merged-old")
            run_git(repo, "checkout", "main")
            _write_text(repo / "README.md", "# updated\n")
            run_git(repo, "add", "README.md")
            run_git(repo, "commit", "-m", "ahead")

            sync = asw.check_git_sync(repo, prod, use_git=True)
            self.assertFalse(sync["head_in_sync"])
            self.assertIn("merged-old", sync["repo"]["merged_local_branches"])

    def test_invalid_arguments_return_2(self) -> None:
        self.assertEqual(asw.main(["--days", "0"]), 2)
        self.assertEqual(asw.main(["--days", "10", "--window-days", "5"]), 2)
        self.assertEqual(asw.main(["--now", "2026-11-27T00:00:00"]), 2)


if __name__ == "__main__":
    unittest.main()
