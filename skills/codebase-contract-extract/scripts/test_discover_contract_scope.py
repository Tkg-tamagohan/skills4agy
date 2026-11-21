#!/usr/bin/env python3
"""discover_contract_scope.py の単体テスト（CE-01〜CE-06）。

Python 標準ライブラリ `unittest` のみを用い、`tempfile.TemporaryDirectory` 上で
BFS 探索・剪定・後行順、承認閾値とモード境界、ファイル優先順と除外、
`.env` 遮断とシンボリックリンク非追従、チャンク分割、CLI 出力を検証する。
"""

from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

_SCRIPT_DIR = Path(__file__).resolve().parent
if str(_SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPT_DIR))

import discover_contract_scope as dcs  # noqa: E402


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _write_lines(path: Path, count: int, prefix: str = "x = 1") -> None:
    content = "\n".join(f"{prefix}  # line {i + 1}" for i in range(count)) + "\n"
    _write_text(path, content)


class TestDiscoverContractScope(unittest.TestCase):
    """CE-01〜CE-06 の決定論的テスト群。"""

    def test_ce01_bfs_pruning_and_postorder_kinds(self) -> None:
        """CE-01: 除外・空・テスト専用ディレクトリを剪定し、後行順と kind を正しく返す。"""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            # .gitignore による除外（ignored_dir/ と *.gen.py）
            _write_text(root / ".gitignore", "ignored_dir/\n*.gen.py\n")

            # 除外対象ディレクトリ群
            _write_text(root / ".git" / "config.py", "a = 1\n")
            _write_text(root / "node_modules" / "pkg" / "index.js", "module.exports = {};\n")
            _write_text(root / "__pycache__" / "mod.py", "a = 1\n")
            _write_text(root / "ignored_dir" / "secret.py", "a = 1\n")
            _write_text(root / "tests" / "test_app.py", "def test_ok(): pass\n")
            _write_text(root / "__tests__" / "a.spec.ts", "test('x', () => {});\n")

            # 非本番ファイルのみのディレクトリ（ボトムアップ剪定される）
            _write_text(root / "docs_only" / "guide.md", "# guide\n")
            _write_text(root / "test_files_only" / "helper_test.go", "package main\n")
            _write_text(root / "empty_parent" / "empty_child" / "styles.css", "body {}\n")

            # 本番ツリー: root -> src (intermediate) -> src/api (leaf), src/db (leaf)
            _write_text(root / "pyproject.toml", "[project]\nname='demo'\n")
            _write_text(root / "src" / "main.py", "print('main')\n")
            _write_text(root / "src" / "generated.gen.py", "x = 1\n")
            _write_text(root / "src" / "api" / "handler.py", "def handle(): pass\n")
            _write_text(root / "src" / "db" / "schema.sql", "CREATE TABLE t (id INT);\n")

            payload = dcs.discover_scope(root)
            dirs = payload["directories"]
            assert isinstance(dirs, list)

            paths_and_kinds = [(d["path"], d["kind"]) for d in dirs]
            self.assertEqual(
                paths_and_kinds,
                [
                    ("src/api", "leaf"),
                    ("src/db", "leaf"),
                    ("src", "intermediate"),
                    (".", "root"),
                ],
            )
            self.assertEqual(payload["dir_count"], 4)
            # src/generated.gen.py は .gitignore により除外されている
            src_files = [f["path"] for c in dirs[2]["chunks"] for f in c["files"]]
            self.assertEqual(src_files, ["src/main.py"])

    def test_ce02_approval_threshold_and_mode_boundaries(self) -> None:
        """CE-02: dir_count > 15 で requires_approval=true、5/6 で direct/delegated が切り替わる。"""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            # 4 つの leaf + 1 つの root = 計 5 ディレクトリ（direct, approval 不要）
            _write_text(root / "pyproject.toml", "[project]\nname='boundary'\n")
            for i in range(4):
                _write_text(root / f"pkg_{i:02d}" / "mod.py", f"VAL = {i}\n")

            res_5 = dcs.discover_scope(root)
            self.assertEqual(res_5["dir_count"], 5)
            self.assertEqual(res_5["recommended_mode"], "direct")
            self.assertFalse(res_5["requires_approval"])

            # 1 ディレクトリ追加で計 6 ディレクトリ（delegated, approval 不要）
            _write_text(root / "pkg_04" / "mod.py", "VAL = 4\n")
            res_6 = dcs.discover_scope(root)
            self.assertEqual(res_6["dir_count"], 6)
            self.assertEqual(res_6["recommended_mode"], "delegated")
            self.assertFalse(res_6["requires_approval"])

            # 計 15 ディレクトリまで追加（requires_approval=False の上限）
            for i in range(5, 14):
                _write_text(root / f"pkg_{i:02d}" / "mod.py", f"VAL = {i}\n")
            res_15 = dcs.discover_scope(root)
            self.assertEqual(res_15["dir_count"], 15)
            self.assertEqual(res_15["recommended_mode"], "delegated")
            self.assertFalse(res_15["requires_approval"])

            # 16 ディレクトリ目で requires_approval=True
            _write_text(root / "pkg_14" / "mod.py", "VAL = 14\n")
            res_16 = dcs.discover_scope(root)
            self.assertEqual(res_16["dir_count"], 16)
            self.assertEqual(res_16["recommended_mode"], "delegated")
            self.assertTrue(res_16["requires_approval"])

    def test_ce03_file_priority_and_exclusions(self) -> None:
        """CE-03: schema/build -> entrypoint -> source 昇順の優先順位と除外規則を検証する。"""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            # 採用対象（意図的に逆順や混在名で配置）
            _write_text(root / "z_worker.py", "def run(): pass\n")
            _write_text(root / "a_client.py", "def call(): pass\n")
            _write_text(root / "main.py", "def main(): pass\n")
            _write_text(root / "__init__.py", "__all__ = []\n")
            _write_text(root / "service.proto", 'syntax = "proto3";\n')
            _write_text(root / "pyproject.toml", "[project]\nname='x'\n")

            # 除外対象群
            _write_text(root / "test_worker.py", "def test_w(): pass\n")
            _write_text(root / "worker_test.go", "package main\n")
            _write_text(root / "UserTest.java", "class UserTest {}\n")
            _write_text(root / "api.spec.ts", "describe('a', () => {});\n")
            _write_text(root / "package-lock.json", "{}\n")
            _write_text(root / "uv.lock", "version = 1\n")
            _write_text(root / "theme.css", "body {}\n")
            _write_text(root / "layout.scss", "$a: 1;\n")
            _write_text(root / "README.md", "# readme\n")
            (root / "broken.py").write_bytes(b"\xff\xfe\x00\x01invalid")

            payload = dcs.discover_scope(root)
            dirs = payload["directories"]
            assert isinstance(dirs, list)
            self.assertEqual(len(dirs), 1)
            files = [f["path"] for c in dirs[0]["chunks"] for f in c["files"]]
            self.assertEqual(
                files,
                [
                    "pyproject.toml",
                    "service.proto",
                    "__init__.py",
                    "main.py",
                    "a_client.py",
                    "z_worker.py",
                ],
            )

    def test_ce04_blocked_env_and_symlink_non_following(self) -> None:
        """CE-04: .env 秘密ファイル除外とシンボリックリンク非追従を検証する。"""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_text(root / "app.py", "print('ok')\n")
            _write_text(root / ".env", "API_KEY=secret\n")
            _write_text(root / ".env.local", "TOKEN=secret\n")
            _write_text(root / ".env.production", "DB_PASS=secret\n")
            _write_text(root / ".env.example", "API_KEY=\n")

            outside = root / "outside_target"
            _write_text(outside / "leak.py", "SECRET = 1\n")

            symlink_created = False
            link_dir = root / "linked_dir"
            link_file = root / "linked_file.py"
            try:
                os.symlink(outside, link_dir, target_is_directory=True)
                os.symlink(outside / "leak.py", link_file, target_is_directory=False)
                symlink_created = True
            except OSError:
                symlink_created = False

            # outside_target を探索対象外にするため .gitignore に追加（リンク経由のみ試す）
            _write_text(root / ".gitignore", "outside_target/\n")

            if symlink_created:
                payload = dcs.discover_scope(root)
                dirs = payload["directories"]
                assert isinstance(dirs, list)
                all_files = [
                    f["path"]
                    for d in dirs
                    for c in d["chunks"]
                    for f in c["files"]
                ]
                self.assertEqual(all_files, ["app.py"])
                self.assertEqual([d["path"] for d in dirs], ["."])
            else:
                # Windows で権限不足により os.symlink が作れない場合も、
                # os.scandir の is_symlink()==True と follow_symlinks=False の非追従を検証する
                fake_link_dir = mock.MagicMock()
                fake_link_dir.name = "linked_dir"
                fake_link_dir.path = str(root / "linked_dir")
                fake_link_dir.is_symlink.return_value = True
                fake_link_dir.is_dir.return_value = True
                fake_link_dir.is_file.return_value = False

                real_scandir = os.scandir

                def _scandir_with_fake_symlink(path: Path | str):
                    ctx = real_scandir(path)
                    if Path(path).resolve() == root.resolve():
                        entries = list(ctx) + [fake_link_dir]
                        ctx.close()

                        class _FakeCtx:
                            def __enter__(self_inner):
                                return iter(entries)

                            def __exit__(self_inner, *args):
                                return False

                        return _FakeCtx()
                    return ctx

                with mock.patch.object(dcs.os, "scandir", side_effect=_scandir_with_fake_symlink):
                    payload = dcs.discover_scope(root)
                fake_link_dir.is_symlink.assert_called_once_with()
                fake_link_dir.is_dir.assert_not_called()
                dirs = payload["directories"]
                assert isinstance(dirs, list)
                all_files = [
                    f["path"]
                    for d in dirs
                    for c in d["chunks"]
                    for f in c["files"]
                ]
                self.assertEqual(all_files, ["app.py"])

    def test_ce05_chunk_packing_and_oversized_file(self) -> None:
        """CE-05: --chunk-lines による複数ファイル梱包と単一超過ファイルの非分割を検証する。"""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_lines(root / "a.py", 60)
            _write_lines(root / "b.py", 50)
            _write_lines(root / "c.py", 150)  # 100 行上限を超過する単一ファイル
            _write_lines(root / "d.py", 40)

            payload = dcs.discover_scope(root, chunk_lines=100)
            dirs = payload["directories"]
            assert isinstance(dirs, list)
            self.assertEqual(len(dirs), 1)
            dir_entry = dirs[0]
            self.assertEqual(dir_entry["total_lines"], 300)

            chunks = dir_entry["chunks"]
            self.assertEqual(len(chunks), 4)
            self.assertEqual([f["path"] for f in chunks[0]["files"]], ["a.py"])
            self.assertEqual(chunks[0]["total_lines"], 60)
            self.assertEqual([f["path"] for f in chunks[1]["files"]], ["b.py"])
            self.assertEqual(chunks[1]["total_lines"], 50)
            self.assertEqual([f["path"] for f in chunks[2]["files"]], ["c.py"])
            self.assertEqual(chunks[2]["total_lines"], 150)
            self.assertEqual([f["path"] for f in chunks[3]["files"]], ["d.py"])
            self.assertEqual(chunks[3]["total_lines"], 40)

            # 40 + 50 <= 100 の場合は同一チャンクへ梱包される
            _write_lines(root / "e.py", 40)
            payload2 = dcs.discover_scope(root, chunk_lines=100)
            chunks2 = payload2["directories"][0]["chunks"]
            self.assertEqual([f["path"] for f in chunks2[3]["files"]], ["d.py", "e.py"])
            self.assertEqual(chunks2[3]["total_lines"], 80)

    def test_ce06_cli_json_and_table_output(self) -> None:
        """CE-06: CLI の --format json と --format table 出力、不正ルート時の終了コードを検証する。"""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_lines(root / "sub" / "main.py", 10)
            _write_lines(root / "sub" / "util.py", 15)

            script_path = Path(dcs.__file__).resolve()
            env = os.environ.copy()
            env["PYTHONUTF8"] = "1"
            env["PYTHONIOENCODING"] = "utf-8"

            json_proc = subprocess.run(
                [sys.executable, str(script_path), "--root", str(root), "--format", "json"],
                capture_output=True,
                text=True,
                encoding="utf-8",
                env=env,
                check=False,
            )
            self.assertEqual(json_proc.returncode, 0, msg=json_proc.stderr)
            parsed = json.loads(json_proc.stdout)
            self.assertEqual(parsed["dir_count"], 2)
            self.assertEqual(parsed["recommended_mode"], "direct")
            self.assertFalse(parsed["requires_approval"])
            self.assertEqual([d["path"] for d in parsed["directories"]], ["sub", "."])

            table_proc = subprocess.run(
                [sys.executable, str(script_path), "--root", str(root), "--format", "table"],
                capture_output=True,
                text=True,
                encoding="utf-8",
                env=env,
                check=False,
            )
            self.assertEqual(table_proc.returncode, 0, msg=table_proc.stderr)
            self.assertIn("dir_count: 2", table_proc.stdout)
            self.assertIn("recommended_mode: direct", table_proc.stdout)
            self.assertIn("| # | path | kind | files | total_lines | chunks |", table_proc.stdout)
            self.assertIn("`sub`", table_proc.stdout)

            # 存在しないルートは終了コード 2
            buf = io.StringIO()
            err_buf = io.StringIO()
            with redirect_stdout(buf), redirect_stderr(err_buf):
                bad_code = dcs.main(["--root", str(root / "missing")])
            self.assertEqual(bad_code, 2)
            self.assertIn("存在しません", err_buf.getvalue())


if __name__ == "__main__":
    unittest.main()
