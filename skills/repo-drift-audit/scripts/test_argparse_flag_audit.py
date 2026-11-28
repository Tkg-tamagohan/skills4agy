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
        """AFA-04: 同一セグメントに複数スクリプトが混在する場合や接尾辞一致するスクリプト名で誤帰属しない。"""
        lines = [
            "```bash",
            "python run.py sub_run.py --ambiguous",
            "  --dangling-after-mixed",
            "python sub_run.py --sub-flag",
            "```",
            "Mixed inline `run.py sub_run.py --b` should be ignored.",
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

    def test_AFA_07_subcommand_scoped_flags_and_shared_helper(self) -> None:
        """AFA-07: 別サブコマンド専用フラグの誤用を検知し、共有ヘルパや parents 継承フラグは許容する。"""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cli = root / "cli.py"
            cli.write_text(
                "import argparse\n\n"
                "def _add_shared(p: argparse.ArgumentParser) -> None:\n"
                "    p.add_argument('--dry-run', action='store_true')\n\n"
                "def build() -> argparse.ArgumentParser:\n"
                "    base = argparse.ArgumentParser(add_help=False)\n"
                "    base.add_argument('--base-opt')\n"
                "    parser = argparse.ArgumentParser()\n"
                "    parser.add_argument('--global-opt')\n"
                "    subs = parser.add_subparsers(dest='cmd')\n"
                "    d = subs.add_parser('docs', parents=[base])\n"
                "    d.add_argument('--repo')\n"
                "    _add_shared(d)\n"
                "    b = subs.add_parser('backlog')\n"
                "    b.add_argument('--backlog')\n"
                "    _add_shared(b)\n"
                "    return parser\n",
                encoding="utf-8",
            )
            md_bad = root / "bad.md"
            md_bad.write_text(
                "```bash\n"
                "python cli.py docs --repo . --base-opt x --dry-run --backlog BACKLOG.md\n"
                "```\n",
                encoding="utf-8",
            )
            self.assertEqual(afa.find_doc_only_flags([md_bad], [cli]), ["cli.py:--backlog"])

            md_ok = root / "ok.md"
            md_ok.write_text(
                "Run `cli.py backlog --backlog BACKLOG.md --dry-run --global-opt 1`.\n"
                "Run `cli.py --dry-run` (without subcommand).\n",
                encoding="utf-8",
            )
            self.assertEqual(afa.find_doc_only_flags([md_ok], [cli]), [])

            # backlog は base を継承していないため --base-opt を誤用すると検知される
            self.assertEqual(
                afa.find_doc_only_flags_in_text("`cli.py backlog --base-opt 1`", [cli]),
                ["cli.py:--base-opt"],
            )

    def test_AFA_08_subcommand_preserved_across_line_continuations(self) -> None:
        """AFA-08: 複数行継続（\\ や `）でサブコマンド文脈を引き継ぎ、次行の不正フラグを検知する。"""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cli = root / "tool.py"
            cli.write_text(
                "import argparse\n"
                "p = argparse.ArgumentParser()\n"
                "subs = p.add_subparsers(dest='cmd')\n"
                "s1 = subs.add_parser('scan')\n"
                "s1.add_argument('--repo')\n"
                "s2 = subs.add_parser('plan')\n"
                "s2.add_argument('--stdin', action='store_true')\n",
                encoding="utf-8",
            )
            doc_text = (
                "```bash\n"
                "python tool.py scan \\\n"
                "  --repo . \\\n"
                "  --stdin\n"
                "```\n"
            )
            self.assertEqual(afa.find_doc_only_flags_in_text(doc_text, [cli]), ["tool.py:--stdin"])

    def test_AFA_09_chained_commands_preserve_per_segment_subcommands(self) -> None:
        """AFA-09: && や ; で連結されたコマンドで各セグメントのサブコマンド固有フラグを正しく許容する。"""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cli = root / "preflight_drift.py"
            cli.write_text(
                "import argparse\n"
                "p = argparse.ArgumentParser()\n"
                "subs = p.add_subparsers(dest='cmd')\n"
                "s = subs.add_parser('scan')\n"
                "s.add_argument('--repo')\n"
                "pt = subs.add_parser('plan-tracks')\n"
                "pt.add_argument('--plans-json')\n",
                encoding="utf-8",
            )
            doc_ok = (
                "```bash\n"
                "python preflight_drift.py scan --repo . && python preflight_drift.py plan-tracks --plans-json plans.json\n"
                "```\n"
                "Inline: `preflight_drift.py scan --repo . && preflight_drift.py plan-tracks --plans-json plans.json`\n"
            )
            self.assertEqual(afa.find_doc_only_flags_in_text(doc_ok, [cli]), [])

            doc_bad = (
                "```bash\n"
                "python preflight_drift.py scan --plans-json bad.json && python preflight_drift.py plan-tracks --repo .\n"
                "```\n"
            )
            self.assertEqual(
                afa.find_doc_only_flags_in_text(doc_bad, [cli]),
                ["preflight_drift.py:--plans-json", "preflight_drift.py:--repo"],
            )

    def test_AFA_10_class_method_and_nested_func_add_argument_collected(self) -> None:
        """AFA-10: ClassDef 内のメソッドやネスト関数で定義された add_argument が漏れない。"""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cli = root / "cls_cli.py"
            cli.write_text(
                "import argparse\n\n"
                "class Cli:\n"
                "    @classmethod\n"
                "    def build(cls) -> argparse.ArgumentParser:\n"
                "        parser = argparse.ArgumentParser()\n"
                "        parser.add_argument('--output-dir')\n"
                "        def add_nested(p: argparse.ArgumentParser) -> None:\n"
                "            p.add_argument('--nested-opt')\n"
                "        add_nested(parser)\n"
                "        return parser\n",
                encoding="utf-8",
            )
            self.assertEqual(
                afa.extract_argparse_flags(cli),
                {"--nested-opt", "--output-dir"},
            )
            self.assertEqual(
                afa.find_doc_only_flags_in_text(
                    "`cls_cli.py --output-dir out --nested-opt 1`", [cli]
                ),
                [],
            )

    def test_AFA_11_repeated_parent_factory_calls_inherit_for_all_subcommands(self) -> None:
        """AFA-11: 複数サブコマンドが同じ親パーサー生成関数 parents=[common()] を呼んでも全サブコマンドへ継承される。"""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cli = root / "multi_parent.py"
            cli.write_text(
                "import argparse\n\n"
                "def common() -> argparse.ArgumentParser:\n"
                "    p = argparse.ArgumentParser(add_help=False)\n"
                "    p.add_argument('--common-flag')\n"
                "    return p\n\n"
                "def build() -> argparse.ArgumentParser:\n"
                "    root_p = argparse.ArgumentParser()\n"
                "    subs = root_p.add_subparsers(dest='cmd')\n"
                "    a = subs.add_parser('alpha', parents=[common()])\n"
                "    a.add_argument('--alpha-only')\n"
                "    b = subs.add_parser('beta', parents=[common()])\n"
                "    b.add_argument('--beta-only')\n"
                "    return root_p\n",
                encoding="utf-8",
            )
            doc_ok = (
                "`multi_parent.py alpha --common-flag 1 --alpha-only 2`\n"
                "`multi_parent.py beta --common-flag 1 --beta-only 2`\n"
            )
            self.assertEqual(afa.find_doc_only_flags_in_text(doc_ok, [cli]), [])

    def test_AFA_12_module_func_isolated_from_unrelated_class_method_collision(self) -> None:
        """AFA-12: 同名クラスメソッド Other.configure() があってもモジュール関数 configure(alpha) を誤帰属させない。"""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cli = root / "scoped.py"
            cli.write_text(
                "import argparse\n\n"
                "class Other:\n"
                "    def configure(self) -> None:\n"
                "        pass\n\n"
                "def configure(p: argparse.ArgumentParser) -> None:\n"
                "    p.add_argument('--alpha-only')\n\n"
                "def build() -> argparse.ArgumentParser:\n"
                "    root_p = argparse.ArgumentParser()\n"
                "    subs = root_p.add_subparsers(dest='cmd')\n"
                "    alpha = subs.add_parser('alpha')\n"
                "    configure(alpha)\n"
                "    beta = subs.add_parser('beta')\n"
                "    beta.add_argument('--beta-only')\n"
                "    return root_p\n",
                encoding="utf-8",
            )
            self.assertEqual(
                afa.find_doc_only_flags_in_text("`scoped.py alpha --alpha-only`", [cli]),
                [],
            )
            self.assertEqual(
                afa.find_doc_only_flags_in_text("`scoped.py beta --alpha-only`", [cli]),
                ["scoped.py:--alpha-only"],
            )

    def test_AFA_13_nested_closure_preserves_outer_subparser_binding(self) -> None:
        """AFA-13: ネスト関数が外側のサブパーサー変数 alpha をクロージャ参照しても他サブコマンドへ漏れない。"""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cli = root / "closure_cli.py"
            cli.write_text(
                "import argparse\n\n"
                "def build() -> argparse.ArgumentParser:\n"
                "    root_p = argparse.ArgumentParser()\n"
                "    subs = root_p.add_subparsers(dest='cmd')\n"
                "    alpha = subs.add_parser('alpha')\n"
                "    beta = subs.add_parser('beta')\n"
                "    beta.add_argument('--beta-only')\n"
                "    def configure() -> None:\n"
                "        alpha.add_argument('--alpha-only')\n"
                "    configure()\n"
                "    return root_p\n",
                encoding="utf-8",
            )
            self.assertEqual(
                afa.find_doc_only_flags_in_text("`closure_cli.py alpha --alpha-only`", [cli]),
                [],
            )
            self.assertEqual(
                afa.find_doc_only_flags_in_text("`closure_cli.py beta --alpha-only`", [cli]),
                ["closure_cli.py:--alpha-only"],
            )

    def test_AFA_14_escaped_pipe_and_semicolon_do_not_split_flags(self) -> None:
        """AFA-14: バックスラッシュエスケープされた \\| や \\; で分割せず後続の不在フラグを検出する。"""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cli = root / "tool.py"
            cli.write_text(
                "import argparse\n"
                "p = argparse.ArgumentParser()\n"
                "p.add_argument('--pattern')\n",
                encoding="utf-8",
            )
            doc_text = (
                "```bash\n"
                "python tool.py --pattern foo\\|bar --typo\n"
                "```\n"
                "Inline: `tool.py --pattern foo\\;bar --typo-inline`\n"
            )
            self.assertEqual(
                afa.find_doc_only_flags_in_text(doc_text, [cli]),
                ["tool.py:--typo", "tool.py:--typo-inline"],
            )


if __name__ == "__main__":
    unittest.main()
