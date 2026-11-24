"""check_hygiene.py の単体テスト（CH-01〜CH-09）。

テストケースの ID 採番と報告は rule `test-conventions` に従う。
実行: `python test_check_hygiene.py`（同ディレクトリから）
"""

import contextlib
import io
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import check_hygiene


def _write_clean_repo(root: Path) -> None:
    (root / "app.py").write_text("def hello():\n    return 'ok'\n", encoding="utf-8")
    (root / "data.json").write_text(
        json.dumps({"name": "sample"}, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    (root / "README.md").write_text(
        "# 見出し\n\nこれは正常な日本語の文である。\n", encoding="utf-8"
    )
    (root / "config.yml").write_text("enabled: true\n", encoding="utf-8")


def _init_git(root: Path) -> None:
    for args in (
        ("init", "-q"),
        ("config", "user.email", "test@example.com"),
        ("config", "user.name", "test"),
        ("add", "-A"),
        ("commit", "-qm", "init"),
    ):
        subprocess.run(["git", *args], cwd=root, check=True, capture_output=True)


class TestCheckHygiene(unittest.TestCase):
    """check_hygiene.py の構文・文字コード・競合マーカー・slop_lint 検査（CH-01〜CH-09）。"""

    def make_repo(self, *, init_git: bool = False) -> Path:
        root = Path(tempfile.mkdtemp(prefix="check-hygiene-test-"))
        self.addCleanup(shutil.rmtree, root, True)
        _write_clean_repo(root)
        if init_git:
            _init_git(root)
        return root

    def run_cli(self, *args: str) -> tuple[int, str]:
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = check_hygiene.main(list(args))
        return rc, buf.getvalue()

    def test_ch_01_正常リポジトリはGitと非Git双方で通過しpycacheを残さない(self):
        for use_git in (True, False):
            with self.subTest(init_git=use_git):
                root = self.make_repo(init_git=use_git)
                rc, out = self.run_cli("--root", str(root))
                self.assertEqual(rc, 0, out)
                self.assertIn("[PASS] py_compile", out)
                self.assertIn("[PASS] json.loads", out)
                self.assertIn("[PASS] text hygiene", out)
                self.assertIn("[PASS] slop_lint --strict", out)
                self.assertEqual([], list(root.rglob("__pycache__")))

    def test_ch_02_未追跡ファイルの違反を検出しgitignore対象を無視する(self):
        root = self.make_repo(init_git=True)
        (root / ".gitignore").write_text("ignored/\n", encoding="utf-8")
        subprocess.run(["git", "add", ".gitignore"], cwd=root, check=True, capture_output=True)
        subprocess.run(["git", "commit", "-qm", "add gitignore"], cwd=root, check=True, capture_output=True)

        # .gitignore 対象内の違反は無視される
        (root / "ignored").mkdir()
        (root / "ignored" / "bad.py").write_text("def broken(:\n", encoding="utf-8")
        rc, out = self.run_cli("--root", str(root))
        self.assertEqual(rc, 0, out)

        # git add 前の新規未追跡ファイルの違反は検出される
        (root / "untracked_bad.py").write_text("def broken(:\n", encoding="utf-8")
        rc, out = self.run_cli("--root", str(root))
        self.assertEqual(rc, 1, out)
        self.assertIn("untracked_bad.py", out)

    def test_ch_03_py構文エラーとpyゼロ件を拒否する(self):
        root_bad = self.make_repo()
        (root_bad / "bad.py").write_text("def broken(:\n", encoding="utf-8")
        rc, out = self.run_cli("--root", str(root_bad))
        self.assertEqual(rc, 1, out)
        self.assertIn("bad.py", out)

        root_empty = self.make_repo()
        (root_empty / "app.py").unlink()
        rc, out = self.run_cli("--root", str(root_empty))
        self.assertEqual(rc, 1, out)
        self.assertIn("no Python files found", out)

    def test_ch_04_不正JSONと非標準定数とJSONゼロ件を拒否する(self):
        for payload in ("{invalid", '{"x": NaN}', '{"x": Infinity}', '{"x": -Infinity}'):
            with self.subTest(payload=payload):
                root = self.make_repo()
                (root / "bad.json").write_text(payload, encoding="utf-8")
                rc, out = self.run_cli("--root", str(root))
                self.assertEqual(rc, 1, out)
                self.assertIn("bad.json", out)

        root_empty = self.make_repo()
        (root_empty / "data.json").unlink()
        rc, out = self.run_cli("--root", str(root_empty))
        self.assertEqual(rc, 1, out)
        self.assertIn("no JSON files found", out)

    def test_ch_05_文字コード違反とU_FFFDと競合マーカーを検出し非マーカー区切り線を誤検出しない(self):
        # 不正 UTF-8
        root_utf8 = self.make_repo()
        (root_utf8 / "bad.txt").write_bytes(b"\xff\xfe\x80")
        rc, out = self.run_cli("--root", str(root_utf8))
        self.assertEqual(rc, 1, out)
        self.assertIn("UTF-8 decode error", out)

        # U+FFFD
        root_fffd = self.make_repo()
        (root_fffd / "bad.txt").write_text("壊れた文字: \ufffd\n", encoding="utf-8")
        rc, out = self.run_cli("--root", str(root_fffd))
        self.assertEqual(rc, 1, out)
        self.assertIn("U+FFFD", out)

        # 行頭競合マーカー 3 種
        for marker in ("<<<<<<< HEAD", "=======", ">>>>>>> branch"):
            with self.subTest(marker=marker):
                root_conf = self.make_repo()
                (root_conf / "conflict.md").write_text(f"# 見出し\n\n{marker}\n", encoding="utf-8")
                rc, out = self.run_cli("--root", str(root_conf), "--skip-slop-lint")
                self.assertEqual(rc, 1, out)
                self.assertIn("conflict marker", out)

        # 非マーカー区切り線（インデント付き、または単独行でない）は誤検出しない
        root_ok = self.make_repo()
        (root_ok / "notes.txt").write_text("  =======\n======= title\n", encoding="utf-8")
        rc, out = self.run_cli("--root", str(root_ok))
        self.assertEqual(rc, 0, out)

    def test_ch_06_slop_lint連携がwarnを検出しinfoのみを通過させる(self):
        # warn（nakaguro_parallel）を含む場合は失敗
        root_warn = self.make_repo()
        (root_warn / "doc.md").write_text(
            "# 見出し\n\n機能の追加・変更を行う。\n", encoding="utf-8"
        )
        rc, out = self.run_cli("--root", str(root_warn))
        self.assertEqual(rc, 1, out)
        self.assertIn("doc.md", out)
        self.assertIn("slop_lint --strict", out)

        # info のみ（太字ラベル定義など）は通過
        root_info = self.make_repo()
        (root_info / "doc.md").write_text(
            "# 見出し\n\n- **項目**：これは定義の説明である。\n", encoding="utf-8"
        )
        rc, out = self.run_cli("--root", str(root_info))
        self.assertEqual(rc, 0, out)

    def test_ch_07_sloplintignoreと恒久除外とskipフラグが機能する(self):
        root = self.make_repo()
        (root / "ignored_doc.md").write_text(
            "# 見出し\n\n機能の追加・変更を行う。\n", encoding="utf-8"
        )
        ref_dir = root / "references"
        ref_dir.mkdir()
        (ref_dir / "slop-catalog.md").write_text(
            "# カタログ\n\n機能の追加・変更を行う。\n", encoding="utf-8"
        )
        (root / ".sloplintignore").write_text("ignored_doc.md\n", encoding="utf-8")

        rc, out = self.run_cli("--root", str(root))
        self.assertEqual(rc, 0, out)

        # 未除外の違反ファイルでも --skip-slop-lint なら通過する
        (root / "unignored.md").write_text(
            "# 見出し\n\n機能の追加・変更を行う。\n", encoding="utf-8"
        )
        rc_fail, _ = self.run_cli("--root", str(root))
        self.assertEqual(rc_fail, 1)

        rc_skip, out_skip = self.run_cli("--root", str(root), "--skip-slop-lint")
        self.assertEqual(rc_skip, 0, out_skip)
        self.assertNotIn("slop_lint --strict", out_skip)

    def test_ch_08_実リポジトリに対する統合スモーク検査が通過する(self):
        rc, out = self.run_cli("--tracked-only")
        self.assertEqual(rc, 0, out)

    def test_ch_09_sloplintignoreのgitignore互換照合とtracked_only切替を確認する(self):
        # 1. 非 Git と Git 双方で skills/*.md が配下サブディレクトリまで除外しないことを確認する
        for use_git in (False, True):
            with self.subTest(init_git=use_git):
                root = self.make_repo(init_git=use_git)
                (root / ".sloplintignore").write_text("skills/*.md\n", encoding="utf-8")
                (root / "skills").mkdir()
                (root / "skills" / "top.md").write_text(
                    "# 直下\n\n機能の追加・変更を行う。\n", encoding="utf-8"
                )
                (root / "skills" / "sub").mkdir()
                (root / "skills" / "sub" / "nested.md").write_text(
                    "# 配下\n\n機能の追加・変更を行う。\n", encoding="utf-8"
                )
                if use_git:
                    subprocess.run(["git", "add", "-A"], cwd=root, check=True, capture_output=True)
                    subprocess.run(
                        ["git", "commit", "-qm", "add skills"],
                        cwd=root,
                        check=True,
                        capture_output=True,
                    )

                rc, out = self.run_cli("--root", str(root))
                self.assertEqual(rc, 1, out)
                self.assertNotIn("skills/top.md", out)
                self.assertIn("skills/sub/nested.md", out)

                # ** を使えば配下も含めて除外される
                (root / ".sloplintignore").write_text("skills/**/*.md\n", encoding="utf-8")
                rc_glob, out_glob = self.run_cli("--root", str(root))
                self.assertEqual(rc_glob, 0, out_glob)

        # 2. Git 管理下で未追跡ファイルの下書きは --tracked-only で除外され、既定時は検出される
        git_root = self.make_repo(init_git=True)
        (git_root / "draft.md").write_text(
            "# 下書き\n\n機能の追加・変更を行う。\n", encoding="utf-8"
        )
        rc_default, out_default = self.run_cli("--root", str(git_root))
        self.assertEqual(rc_default, 1, out_default)
        self.assertIn("draft.md", out_default)

        rc_tracked, out_tracked = self.run_cli("--root", str(git_root), "--tracked-only")
        self.assertEqual(rc_tracked, 0, out_tracked)


if __name__ == "__main__":
    unittest.main()
