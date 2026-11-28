#!/usr/bin/env python3
"""argparse_flag_audit.py のオフライン単体テスト（AFA-01〜AFA-06）。"""

from __future__ import annotations

from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

_SCRIPT_DIR = Path(__file__).resolve().parent
if str(_SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPT_DIR))

import argparse_flag_audit as afa  # noqa: E402


class ArgparseFlagAuditTests(unittest.TestCase):
    def test_AFA_01_extract_argparse_flags_ast_and_safety(self) -> None:
        """AFA-01: AST からロングフラグを抽出し、短縮フラグ・構文エラー・リパースポイントを安全に除外する。"""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            valid_py = root / "tool.py"
            valid_py.write_text(
                "import argparse\n\n"
                "def build() -> argparse.ArgumentParser:\n"
                "    p = argparse.ArgumentParser()\n"
                "    p.add_argument('-v', '--verbose', action='store_true')\n"
                "    p.add_argument('--output-dir', default='.')\n"
                "    p.add_argument('--')\n"
                "    grp = p.add_argument_group('extra')\n"
                "    grp.add_argument('--dry-run', action='store_true')\n"
                "    return p\n",
                encoding="utf-8",
            )
            self.assertEqual(
                afa.extract_argparse_flags(valid_py),
                {"--verbose", "--output-dir", "--dry-run"},
            )

            bad_py = root / "broken.py"
            bad_py.write_text("def oops(:\n", encoding="utf-8")
            self.assertEqual(afa.extract_argparse_flags(bad_py), set())
            self.assertEqual(afa.extract_argparse_flags(root / "missing.py"), set())

            with mock.patch.object(afa, "_is_reparse_or_symlink", return_value=True):
                self.assertEqual(afa.extract_argparse_flags(valid_py), set())

    def test_AFA_02_strip_quoted_arg_values(self) -> None:
        """AFA-02: クォート内の疑似フラグを除去しつつ外側のコマンドフラグを残す。"""
        line = 'python run.py --command "git push --force" --filter \'--inner-only\' --dry-run'
        stripped = afa.strip_quoted_arg_values(line)
        self.assertIn("--command", stripped)
        self.assertIn("--filter", stripped)
        self.assertIn("--dry-run", stripped)
        self.assertNotIn("--force", stripped)
        self.assertNotIn("--inner-only", stripped)

    def test_AFA_03_extract_doc_flags_fences_continuations_and_backticks(self) -> None:
        """AFA-03: フェンスコードブロック（複数行継続含む）とインラインバッククォートの両方から抽出する。"""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            md = root / "SKILL.md"
            md.write_text(
                "# Demo\n\n"
                "Run `alpha.py --inline-flag` directly.\n\n"
                "```powershell\n"
                "python scripts/alpha.py `\n"
                "  --pwsh-cont `\n"
                "  --second-flag\n"
                "# comment resets active script\n"
                "  --after-comment\n"
                "```\n\n"
                "~~~bash\n"
                "python3 scripts/beta.py \\\n"
                "  --bash-cont\n"
                "~~~\n",
                encoding="utf-8",
            )
            extracted = afa.extract_doc_flags_by_script([md], {"alpha.py", "beta.py"})
            self.assertEqual(
                extracted["alpha.py"],
                {"--inline-flag", "--pwsh-cont", "--second-flag"},
            )
            self.assertNotIn("--after-comment", extracted["alpha.py"])
            self.assertEqual(extracted["beta.py"], {"--bash-cont"})

    def test_AFA_04_mixed_script_lines_and_similar_names_not_misattributed(self) -> None:
        """AFA-04: 同一行に複数スクリプトが混在する場合や接尾辞一致するスクリプト名で誤帰属しない。"""
        lines = [
            "```bash",
            "python run.py --valid-run && python sub_run.py --only-sub",
            "  --dangling-after-mixed",
            "python sub_run.py --sub-flag",
            "```",
            "Mixed inline `run.py --a && sub_run.py --b` should be ignored.",
            "Single inline `run.py --single-run` should be kept.",
        ]
        extracted = afa.extract_doc_flags_from_lines(lines, {"run.py", "sub_run.py"})
        self.assertEqual(extracted.get("run.py"), {"--single-run"})
        self.assertEqual(extracted.get("sub_run.py"), {"--sub-flag"})

    def test_AFA_05_find_doc_only_flags_excludes_help_and_sorts(self) -> None:
        """AFA-05: find_doc_only_flags が --help を許容し、不在フラグのみ昇順 script.py:--flag で返す。"""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            s1 = root / "alpha.py"
            s2 = root / "beta.py"
            s1.write_text(
                "import argparse\np = argparse.ArgumentParser()\np.add_argument('--repo')\n",
                encoding="utf-8",
            )
            s2.write_text(
                "import argparse\np = argparse.ArgumentParser()\np.add_argument('--format')\n",
                encoding="utf-8",
            )
            md1 = root / "SKILL.md"
            md1.write_text(
                "Use `beta.py --format --help --ghost-b`.\n"
                "```bash\npython alpha.py --repo . --help --ghost-a\n```\n",
                encoding="utf-8",
            )
            md2 = root / "guide.md"
            md2.write_text("Also `alpha.py --alpha-extra`.\n", encoding="utf-8")

            doc_only = afa.find_doc_only_flags([md1, md2], [s1, s2])
            self.assertEqual(
                doc_only,
                ["alpha.py:--alpha-extra", "alpha.py:--ghost-a", "beta.py:--ghost-b"],
            )

            in_mem = afa.find_doc_only_flags_in_text(md1.read_text(encoding="utf-8"), [s1, s2])
            self.assertEqual(in_mem, ["alpha.py:--ghost-a", "beta.py:--ghost-b"])

    def test_AFA_06_quoted_inner_flags_excluded_from_doc_only_flags(self) -> None:
        """AFA-06: 引数クォート内のフラグ文字列が不在フラグとして誤検知されない。"""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sp = root / "runner.py"
            sp.write_text(
                "import argparse\np = argparse.ArgumentParser()\np.add_argument('--cmd')\n",
                encoding="utf-8",
            )
            md = root / "README.md"
            md.write_text(
                "```bash\n"
                'python runner.py --cmd "git commit --amend --no-verify"\n'
                "```\n",
                encoding="utf-8",
            )
            self.assertEqual(afa.find_doc_only_flags([md], [sp]), [])


if __name__ == "__main__":
    unittest.main()
