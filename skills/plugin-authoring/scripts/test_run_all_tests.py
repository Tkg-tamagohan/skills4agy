#!/usr/bin/env python3
"""run_all_tests.py の単体テスト (RAT-01〜RAT-06)

テストケースの ID 採番と報告は rule `test-conventions` に従う。
ID は RAT-<連番>。

実行: `python skills/plugin-authoring/scripts/test_run_all_tests.py`
"""

from __future__ import annotations

import contextlib
import io
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from typing import List, Tuple

import run_all_tests


class TestRunAllTests(unittest.TestCase):
    """全スキル横断テストランナーの単体テスト (RAT-01〜RAT-06)"""

    def make_temp_repo(self) -> Path:
        root = Path(tempfile.mkdtemp(prefix="run-all-tests-fixture-"))
        (root / "skills").mkdir(parents=True)
        self.addCleanup(shutil.rmtree, root, True)
        return root

    def write_skill_file(self, root: Path, skill: str, rel: str, content: str) -> Path:
        target = root / "skills" / skill / "scripts" / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
        return target

    def run_cli(self, argv: List[str]) -> Tuple[int, str, str]:
        out = io.StringIO()
        err = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = run_all_tests.main(argv)
        return code, out.getvalue(), err.getvalue()

    def test_RAT_01_discovers_all_skills_and_aggregates_counts(self) -> None:
        """RAT-01: 複数スキル配下の test_*.py を兄弟インポート付きで実行し件数を集計する。"""
        root = self.make_temp_repo()
        self.write_skill_file(
            root,
            "alpha-skill",
            "helper.py",
            "def greet() -> str:\n    return 'hello'\n",
        )
        self.write_skill_file(
            root,
            "alpha-skill",
            "test_alpha.py",
            (
                "import unittest\n"
                "import helper\n"
                "class AlphaTests(unittest.TestCase):\n"
                "    def test_one(self):\n"
                "        self.assertEqual('hello', helper.greet())\n"
                "    def test_two(self):\n"
                "        self.assertTrue(True)\n"
            ),
        )
        self.write_skill_file(
            root,
            "beta-skill",
            "test_beta.py",
            (
                "import unittest\n"
                "class BetaTests(unittest.TestCase):\n"
                "    def test_only(self):\n"
                "        self.assertEqual(2, 1 + 1)\n"
            ),
        )

        code, out, err = self.run_cli(["--root", str(root)])
        self.assertEqual(0, code, f"stdout={out}\nstderr={err}")
        self.assertIn("alpha-skill", out)
        self.assertIn("beta-skill", out)
        self.assertIn("2 ファイル / 3 件 (PASS 2, FAIL 0)", out)

    def test_RAT_02_fails_when_zero_tests_run_or_empty_skills(self) -> None:
        """RAT-02: 0 件実行のテストファイルおよびテスト 0 本ツリーを終了コード 1 で失敗させる。"""
        root_zero = self.make_temp_repo()
        self.write_skill_file(root_zero, "empty-tests", "test_empty.py", "import unittest\n")
        code, out, _ = self.run_cli(["--root", str(root_zero)])
        self.assertEqual(1, code, out)
        self.assertIn("FAIL", out)
        self.assertIn("0 件", out)

        root_none = self.make_temp_repo()
        (root_none / "skills" / "no-tests-skill").mkdir()
        code_none, out_none, _ = self.run_cli(["--root", str(root_none)])
        self.assertEqual(1, code_none, out_none)
        self.assertIn("0 件", out_none)

    def test_RAT_03_reports_failure_and_continues_remaining_files(self) -> None:
        """RAT-03: 1 ファイルが失敗しても残りのファイルを継続実行し終了コード 1 を返す。"""
        root = self.make_temp_repo()
        self.write_skill_file(
            root,
            "a-fail",
            "test_fail.py",
            (
                "import unittest\n"
                "class FailTests(unittest.TestCase):\n"
                "    def test_boom(self):\n"
                "        self.fail('intentional failure')\n"
            ),
        )
        self.write_skill_file(
            root,
            "b-pass",
            "test_pass.py",
            (
                "import unittest\n"
                "class PassTests(unittest.TestCase):\n"
                "    def test_ok(self):\n"
                "        self.assertTrue(True)\n"
            ),
        )

        code, out, _ = self.run_cli(["--root", str(root)])
        self.assertEqual(1, code, out)
        self.assertIn("a-fail", out)
        self.assertIn("b-pass", out)
        self.assertIn("PASS 1, FAIL 1", out)
        self.assertIn("intentional failure", out)

    def test_RAT_04_skill_filter_and_unknown_skill_validation(self) -> None:
        """RAT-04: --skill による絞り込みと存在しないスキル指定時の終了コード 2 を確認する。"""
        root = self.make_temp_repo()
        for skill in ("alpha-skill", "beta-skill", "gamma-skill"):
            self.write_skill_file(
                root,
                skill,
                f"test_{skill.replace('-', '_')}.py",
                (
                    "import unittest\n"
                    "class T(unittest.TestCase):\n"
                    "    def test_ok(self):\n"
                    "        self.assertTrue(True)\n"
                ),
            )

        code, out, err = self.run_cli(
            ["--root", str(root), "--skill", "alpha-skill,gamma-skill"]
        )
        self.assertEqual(0, code, f"stdout={out}\nstderr={err}")
        self.assertIn("alpha-skill", out)
        self.assertIn("gamma-skill", out)
        self.assertNotIn("beta-skill", out)

        bad_code, _, bad_err = self.run_cli(["--root", str(root), "--skill", "missing-skill"])
        self.assertEqual(2, bad_code)
        self.assertIn("missing-skill", bad_err)

    def test_RAT_05_isolates_cwd_when_test_writes_to_dot(self) -> None:
        """RAT-05: dir='.' へ一時ファイルを作るテストを実行しても対象リポジトリにファイルが残らない。"""
        root = self.make_temp_repo()
        self.write_skill_file(
            root,
            "dot-writer",
            "test_dot_write.py",
            (
                "import unittest\n"
                "from pathlib import Path\n"
                "class DotWriterTests(unittest.TestCase):\n"
                "    def test_write_dot(self):\n"
                "        Path('leaked_artifact.txt').write_text('temp', encoding='utf-8')\n"
                "        self.assertTrue(Path('leaked_artifact.txt').is_file())\n"
            ),
        )

        caller_cwd = Path.cwd()
        self.assertFalse((caller_cwd / "leaked_artifact.txt").exists())

        code, out, err = self.run_cli(["--root", str(root)])
        self.assertEqual(0, code, f"stdout={out}\nstderr={err}")
        self.assertFalse((root / "leaked_artifact.txt").exists())
        self.assertFalse((root / "skills" / "dot-writer" / "scripts" / "leaked_artifact.txt").exists())
        self.assertFalse((caller_cwd / "leaked_artifact.txt").exists())

    def test_RAT_06_json_output_and_utf8_summary(self) -> None:
        """RAT-06: --format json の構造化出力とマルチバイト文字の UTF-8 出力を確認する。"""
        root = self.make_temp_repo()
        self.write_skill_file(
            root,
            "utf8-skill",
            "test_utf8.py",
            (
                "import unittest\n"
                "class Utf8Tests(unittest.TestCase):\n"
                "    def test_日本語ケース(self):\n"
                "        print('日本語ログ出力')\n"
                "        self.assertTrue(True)\n"
            ),
        )

        code, out, err = self.run_cli(["--root", str(root), "--format", "json", "-v"])
        self.assertEqual(0, code, f"stdout={out}\nstderr={err}")
        payload = json.loads(out)
        self.assertTrue(payload["ok"])
        self.assertEqual(1, payload["total_files"])
        self.assertEqual(1, payload["total_tests"])
        self.assertEqual(1, payload["passed_files"])
        self.assertEqual(0, payload["failed_files"])
        self.assertEqual("utf8-skill", payload["results"][0]["skill"])
        self.assertIn("日本語ログ出力", payload["results"][0]["output"])


if __name__ == "__main__":
    unittest.main()
