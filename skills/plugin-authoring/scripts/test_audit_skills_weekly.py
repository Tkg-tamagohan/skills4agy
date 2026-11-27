#!/usr/bin/env python3
"""audit_skills_weekly.py の単体テスト。"""

from __future__ import annotations

from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

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

    # alpha-skill: スクリプトあり・テストあり・CLI フラグ乖離あり・横断 import あり
    _write_text(
        repo / "skills" / "alpha-skill" / "SKILL.md",
        "---\nname: alpha-skill\n"
        "description: α処理を実行するときに使用する。共有補助は beta-helper に委ねる。\n"
        "---\n\n# αスキル\n\n## 責任範囲の境界\n\n- 詳細設定は `beta-helper` に委ねる。\n\n"
        "## 手順\n\n```powershell\npython \"$HOME/.gemini/config/plugins/shared-skills/skills/alpha-skill/scripts/run_alpha.py\" --real-flag --ghost-flag\n```\n",
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

            # セッション1（3日前・本番利用 + pretool フォールバック）
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

            # セッション2（15日前・28日窓内だが7日窓外、35日前は窓外）
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

            self.assertEqual(data["meta"]["malformed_lines"], 1)
            self.assertEqual(data["meta"]["active_sessions_7d"], 1)
            self.assertEqual(data["meta"]["active_sessions_28d"], 2)

            skills_by_name = {r["name"]: r for r in data["skills"]}
            # alpha-skill: 本番読込1 + スクリプト実行1 = 2 (7d/28d)
            self.assertEqual(skills_by_name["alpha-skill"]["usage_7d"], 2)
            self.assertEqual(skills_by_name["alpha-skill"]["script_runs_7d"], 1)
            self.assertEqual(skills_by_name["alpha-skill"]["test_case_count"], 2)
            self.assertEqual(skills_by_name["alpha-skill"]["doc_only_flags"], ["--ghost-flag"])

            # beta-helper: dev_repo の参照は保守作業であり、35日前は28日窓外なので実利用0
            self.assertEqual(skills_by_name["beta-helper"]["usage_28d"], 0)
            self.assertEqual(skills_by_name["beta-helper"]["maintenance_touches_28d"], 1)
            self.assertIn("prune_or_merge_candidate", skills_by_name["beta-helper"]["tags"])
            self.assertIn("trim_description_candidate", skills_by_name["beta-helper"]["tags"])
            self.assertIn("split_body_candidate", skills_by_name["beta-helper"]["tags"])

            # manual-heavy: 15日前の利用が28日窓に計上され、7日窓は0、mechanization_candidate が付く
            self.assertEqual(skills_by_name["manual-heavy"]["usage_7d"], 0)
            self.assertEqual(skills_by_name["manual-heavy"]["usage_28d"], 1)
            self.assertIn("mechanization_candidate", skills_by_name["manual-heavy"]["tags"])

            rules_by_name = {r["name"]: r for r in data["rules"]}
            self.assertEqual(rules_by_name["alpha-rule"]["usage_7d"], 1)
            self.assertEqual(rules_by_name["dangling-rule"]["usage_28d"], 0)

            # 委譲リンク切れ・横断 import・フックフォールバック・衛生残骸
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

            # Markdown 出力スモーク
            md = asw.render_markdown(data)
            self.assertIn("# 週次 SKILL 監査定量レポート", md)
            self.assertIn("alpha-skill", md)

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

            # repo 側にマージ済み残存ブランチを作成し、1 コミット進める
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
